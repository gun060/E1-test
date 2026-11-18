// Popular Vote server — Express + PostgreSQL + Google Sign-In (ตรวจ ID token ฝั่งเซิร์ฟเวอร์)
const express = require("express"), { Pool } = require("pg"), { OAuth2Client } = require("google-auth-library"), crypto = require("crypto");
const DEFAULT_SHOPS = ["ร้านส้มตำแซ่บ","หมูกระทะเด็กดี","ก๋วยเตี๋ยวเรือ","ไก่ทอดกรอบ","ชานมไข่มุก","ขนมครก","ลูกชิ้นปิ้ง","ไอศกรีมโฮมเมด","ข้าวหมูทอด","โรตีสายไหม","น้ำผลไม้ปั่น","ทาโกยากิ","ข้าวเหนียวมะม่วง","ปอเปี๊ยะทอด","เฟรนช์ฟรายส์","วาฟเฟิลหน้าหวาน","ไส้กรอกอีสาน","บัวลอยไข่หวาน","พิซซ่าชิ้นโต","ขนมปังปิ้ง","น้ำแข็งใส","ข้าวเหนียวหมูปิ้ง","คัพเค้กน่ารัก","ซูชิมือใหม่","กล้วยทอดทอง","สลัดผักสด","โดนัทจิ๋ว"];

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const TEACHERS = (process.env.TEACHER_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean); // อีเมลครูคนแรก (ได้สิทธิ์ครูอัตโนมัติ)
const FLAG_IP = parseInt(process.env.FLAG_IP_VOTES || "8", 10); // IP ที่โหวตเกินนี้จะถูกติดธงให้ครูตรวจ (ไม่ได้บล็อก)
const gclient = new OAuth2Client(CLIENT_ID);
const db = process.env.DATABASE_URL;
const pool = new Pool({ connectionString: db, ssl: db && !/localhost|127\.0\.0\.1/.test(db) ? { rejectUnauthorized: false } : false });
const app = express();
app.set("trust proxy", 1);

const hits = new Map();
function limited(key, max, ms) {
  const now = Date.now(), h = hits.get(key);
  if (!h || h.t < now) { hits.set(key, { n: 1, t: now + ms }); return false; }
  return ++h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.t < n) hits.delete(k); }, 60000).unref();
const ok = (o = {}) => ({ ok: true, ...o }), fail = e => ({ ok: false, error: e });

async function init() {
  await pool.query(`
  CREATE TABLE IF NOT EXISTS shops(id INT PRIMARY KEY, name TEXT NOT NULL, img TEXT NOT NULL DEFAULT '');
  CREATE TABLE IF NOT EXISTS accounts(sub TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT, picture TEXT, role TEXT NOT NULL DEFAULT 'voter', shop_id INT NOT NULL DEFAULT 0, req_role TEXT, req_shop INT, created_at TIMESTAMPTZ DEFAULT now(), last_login TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS ballots(id SERIAL PRIMARY KEY, sub TEXT UNIQUE NOT NULL, email TEXT, shop_id INT NOT NULL, ip TEXT, void BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS adjustments(id SERIAL PRIMARY KEY, shop_id INT NOT NULL, delta INT NOT NULL, reason TEXT NOT NULL, by_user TEXT, created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS sess(token TEXT PRIMARY KEY, sub TEXT NOT NULL, expires TIMESTAMPTZ NOT NULL);
  CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);`);
  for (let i = 0; i < DEFAULT_SHOPS.length; i++)
    await pool.query("INSERT INTO shops(id,name) VALUES($1,$2) ON CONFLICT DO NOTHING", [i + 1, DEFAULT_SHOPS[i]]);
}
const isOpen = async () => (await pool.query("SELECT v FROM settings WHERE k='open'")).rows[0]?.v !== "0";
async function auth(d, roles) { // อ่านบทบาทจากตาราง accounts ทุกครั้ง เมื่อครูอนุมัติสิทธิ์จะมีผลทันที
  if (!d.token) return null;
  const r = await pool.query("SELECT a.* FROM sess s JOIN accounts a ON a.sub=s.sub WHERE s.token=$1 AND s.expires>now()", [String(d.token)]);
  const a = r.rows[0];
  return a && (!roles || roles.includes(a.role)) ? a : null;
}
async function meOf(a) {
  const b = (await pool.query("SELECT shop_id FROM ballots WHERE sub=$1", [a.sub])).rows[0];
  return { email: a.email, name: a.name, picture: a.picture, role: a.role, shopId: a.shop_id, voted: !!b, votedShop: b ? b.shop_id : null, reqRole: a.req_role, reqShop: a.req_shop };
}
const validShop = n => Number.isInteger(n) && n >= 1 && n <= DEFAULT_SHOPS.length;

app.use("/api", express.json({ type: () => true, limit: "20kb" }));

app.get("/api", async (req, res) => { // สาธารณะ: รายชื่อร้าน สถานะ และ Client ID (ไม่มีคะแนน)
  try { res.json({ shops: (await pool.query("SELECT id,name,img FROM shops ORDER BY id")).rows, open: await isOpen(), googleClientId: CLIENT_ID }); }
  catch (e) { res.status(500).json(fail("server")); }
});

app.post("/api", async (req, res) => {
  const d = req.body || {}, act = d.action, ip = req.ip;
  try {
    if (act === "google") {
      if (limited("g:" + ip, 60, 60000)) return res.json(fail("ลองเข้าสู่ระบบถี่เกินไป กรุณารอสักครู่"));
      if (!CLIENT_ID) return res.json(fail("เซิร์ฟเวอร์ยังไม่ได้ตั้งค่า GOOGLE_CLIENT_ID"));
      let p; try { p = (await gclient.verifyIdToken({ idToken: String(d.credential || ""), audience: CLIENT_ID })).getPayload(); } catch (e) { return res.json(fail("ยืนยันบัญชี Google ไม่สำเร็จ")); }
      if (!p.email || !p.email_verified) return res.json(fail("อีเมลของบัญชีนี้ยังไม่ได้รับการยืนยันจาก Google"));
      const email = p.email.toLowerCase();
      await pool.query(`INSERT INTO accounts(sub,email,name,picture) VALUES($1,$2,$3,$4)
        ON CONFLICT(sub) DO UPDATE SET email=$2,name=$3,picture=$4,last_login=now()`, [p.sub, email, p.name || email, p.picture || ""]);
      if (TEACHERS.includes(email)) await pool.query("UPDATE accounts SET role='teacher', req_role=NULL, req_shop=NULL WHERE sub=$1", [p.sub]);
      const token = crypto.randomBytes(32).toString("hex");
      await pool.query("INSERT INTO sess VALUES($1,$2, now()+interval '12 hours')", [token, p.sub]);
      const a = (await pool.query("SELECT * FROM accounts WHERE sub=$1", [p.sub])).rows[0];
      return res.json(ok({ token, me: await meOf(a) }));
    }
    if (act === "logout") { await pool.query("DELETE FROM sess WHERE token=$1", [String(d.token || "")]); return res.json(ok()); }

    const a = await auth(d); if (!a) return res.json(fail("auth"));

    if (act === "me") return res.json(ok({ me: await meOf(a) }));

    if (act === "requestRole") { // สมัครเป็นผู้ขาย/ครู: ได้สิทธิ์จริงเมื่อครูอนุมัติเท่านั้น
      const role = d.role, shop = parseInt(d.shopId, 10);
      if (a.role !== "voter") return res.json(fail("บัญชีนี้มีสิทธิ์อยู่แล้ว"));
      if (!["vendor", "teacher"].includes(role) || (role === "vendor" && !validShop(shop))) return res.json(fail("ข้อมูลไม่ถูกต้อง"));
      await pool.query("UPDATE accounts SET req_role=$2, req_shop=$3 WHERE sub=$1", [a.sub, role, role === "vendor" ? shop : null]);
      return res.json(ok());
    }

    if (act === "vote") {
      if (limited("v:" + ip, 200, 60000)) return res.json(fail("ส่งถี่เกินไป กรุณาลองใหม่"));
      if (!(await isOpen())) return res.json(fail("closed"));
      const shop = parseInt(d.shopId, 10); if (!validShop(shop)) return res.json(fail("bad_shop"));
      if (a.role === "vendor" && a.shop_id === shop) return res.json(fail("own_shop"));
      const r = await pool.query("INSERT INTO ballots(sub,email,shop_id,ip) VALUES($1,$2,$3,$4) ON CONFLICT(sub) DO NOTHING RETURNING id", [a.sub, a.email, shop, ip]);
      return res.json(r.rowCount ? ok() : fail("already_voted"));
    }

    // ---------- เฉพาะผู้ขาย/ครู ----------
    if (!["vendor", "teacher"].includes(a.role)) return res.json(fail("forbidden"));

    if (act === "dash") {
      const rows = (await pool.query(`SELECT s.id,s.name,s.img,COALESCE(v.c,0)::int votes,COALESCE(x.d,0)::int adj FROM shops s
        LEFT JOIN (SELECT shop_id,count(*) c FROM ballots WHERE NOT void GROUP BY 1) v ON v.shop_id=s.id
        LEFT JOIN (SELECT shop_id,sum(delta) d FROM adjustments GROUP BY 1) x ON x.shop_id=s.id ORDER BY s.id`)).rows.map(r => ({ ...r, total: r.votes + r.adj }));
      const open = await isOpen();
      if (a.role === "vendor") { const me = rows.find(r => r.id === a.shop_id); if (!me) return res.json(fail("ไม่พบร้านของบัญชีนี้")); return res.json(ok({ role: "vendor", shop: { id: me.id, name: me.name, img: me.img }, total: me.total, open })); } // ไม่ส่งอันดับให้ผู้ขาย
      rows.sort((x, y) => y.total - x.total || x.id - y.id).forEach((r, i, z) => r.rank = i && r.total === z[i - 1].total ? z[i - 1].rank : i + 1);
      const st = (await pool.query("SELECT count(*)::int total, count(*) FILTER (WHERE void)::int voided FROM ballots")).rows[0];
      return res.json(ok({ role: "teacher", rows, open, stats: st }));
    }
    if (act === "updateShop") {
      if (a.role !== "vendor") return res.json(fail("forbidden"));
      const name = String(d.name || "").trim().slice(0, 40), img = String(d.img || "").trim();
      if (!name || (img && !/^https:\/\//.test(img))) return res.json(fail("ชื่อว่างไม่ได้ และลิงก์รูปต้องขึ้นต้นด้วย https://"));
      await pool.query("UPDATE shops SET name=$2,img=$3 WHERE id=$1", [a.shop_id, name, img]); return res.json(ok());
    }

    // ---------- เฉพาะครู ----------
    if (a.role !== "teacher") return res.json(fail("forbidden"));

    if (act === "adjust") {
      const delta = parseInt(d.delta, 10), reason = String(d.reason || "").trim().slice(0, 120);
      if (!delta || Math.abs(delta) > 1000 || !reason || !validShop(parseInt(d.shopId, 10))) return res.json(fail("ต้องระบุจำนวนคะแนนและเหตุผล"));
      await pool.query("INSERT INTO adjustments(shop_id,delta,reason,by_user) VALUES($1,$2,$3,$4)", [d.shopId, delta, reason, a.email]); return res.json(ok());
    }
    if (act === "setOpen") {
      await pool.query("INSERT INTO settings VALUES('open',$1) ON CONFLICT(k) DO UPDATE SET v=$1", [d.open ? "1" : "0"]); return res.json(ok({ open: !!d.open }));
    }
    if (act === "people") { // คำขอสิทธิ์ที่รออนุมัติ + รายชื่อผู้ขาย/ครู
      const req = (await pool.query("SELECT sub,email,name,req_role,req_shop FROM accounts WHERE req_role IS NOT NULL ORDER BY created_at")).rows;
      const staff = (await pool.query("SELECT sub,email,name,role,shop_id FROM accounts WHERE role<>'voter' ORDER BY role,email")).rows;
      return res.json(ok({ req, staff }));
    }
    if (act === "decide") { // อนุมัติ/ปฏิเสธคำขอ
      const sub = String(d.sub || "");
      if (d.approve) await pool.query("UPDATE accounts SET role=req_role, shop_id=COALESCE(req_shop,0), req_role=NULL, req_shop=NULL WHERE sub=$1 AND req_role IS NOT NULL", [sub]);
      else await pool.query("UPDATE accounts SET req_role=NULL, req_shop=NULL WHERE sub=$1", [sub]);
      return res.json(ok());
    }
    if (act === "revoke") { // ถอนสิทธิ์ (ห้ามถอนตัวเอง)
      if (String(d.sub) === a.sub) return res.json(fail("ถอนสิทธิ์ตัวเองไม่ได้"));
      await pool.query("UPDATE accounts SET role='voter', shop_id=0 WHERE sub=$1", [String(d.sub || "")]); return res.json(ok());
    }
    if (act === "ballots") { // รายการโหวตล่าสุดพร้อมธง IP ที่โหวตถี่ผิดปกติ
      const rows = (await pool.query(`SELECT b.id,b.email,b.shop_id,b.ip,b.void,b.created_at,c.n::int ip_n FROM ballots b
        JOIN (SELECT ip,count(*) n FROM ballots GROUP BY ip) c ON c.ip=b.ip ORDER BY b.id DESC LIMIT 300`)).rows.map(r => ({ ...r, flag: r.ip_n >= FLAG_IP }));
      return res.json(ok({ rows, flagIp: FLAG_IP }));
    }
    if (act === "void") { await pool.query("UPDATE ballots SET void=$2 WHERE id=$1", [parseInt(d.id, 10), !!d.void]); return res.json(ok()); }

    return res.json(fail("unknown"));
  } catch (e) { console.error(e); res.status(500).json(fail("server")); }
});

app.get("/healthz", (q, r) => r.send("ok"));
app.use(express.static(require("path").join(__dirname, "public")));
init().then(() => app.listen(process.env.PORT || 3000, () => console.log("พร้อมใช้งาน"))).catch(e => { console.error(e); process.exit(1); });
