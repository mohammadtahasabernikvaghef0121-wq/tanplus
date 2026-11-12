const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");
const DB_FILE = path.join(DATA_DIR, "db.json");

for (const dir of [DATA_DIR, UPLOAD_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify({ users: [], certificates: [] }, null, 2)
  );
}
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return { users: [], certificates: [] };
  }
}
function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    plan: user.plan || null,
    createdAt: user.createdAt,
  };
}
function currentUser(req) {
  if (!req.session.userId) return null;
  const db = readDB();
  return db.users.find((u) => u.id === req.session.userId) || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user)
    return res.status(401).json({ error: "برای ادامه وارد حساب کاربری شو." });
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || !user.isAdmin)
    return res.status(403).json({ error: "این بخش فقط برای مدیر سایت است." });
  req.user = user;
  next();
}

// Initial admin is created from environment variables on first server start.
(function seedAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;
  const db = readDB();
  if (!db.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
    db.users.push({
      id: "admin_" + Date.now(),
      name: "مدیر تن‌پلاس",
      email: email.toLowerCase(),
      passwordHash: bcrypt.hashSync(password, 12),
      isAdmin: true,
      createdAt: new Date().toISOString(),
      plan: null,
    });
    writeDB(db);
    console.log("Admin account created from ADMIN_EMAIL / ADMIN_PASSWORD.");
  }
})();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "change-this-local-development-secret-before-deploying",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);
app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(path.join(ROOT, "public")));

app.get("/api/me", (req, res) => {
  const user = currentUser(req);
  res.json({
    user: user ? publicUser(user) : null,
    isAdmin: !!(user && user.isAdmin),
  });
});

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || name.trim().length < 2)
    return res.status(400).json({ error: "نام باید حداقل ۲ حرف باشد." });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "ایمیل معتبر وارد کن." });
  if (!password || password.length < 8)
    return res
      .status(400)
      .json({ error: "رمز عبور باید حداقل ۸ کاراکتر باشد." });
  const db = readDB();
  if (db.users.some((u) => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: "این ایمیل قبلاً ثبت شده است." });
  const user = {
    id: "u_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8),
    name: name.trim().slice(0, 70),
    email: email.trim().toLowerCase(),
    passwordHash: await bcrypt.hash(password, 12),
    isAdmin: false,
    plan: null,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  writeDB(db);
  req.session.userId = user.id;
  res.json({ message: "حساب کاربری ساخته شد.", user: publicUser(user) });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const db = readDB();
  const user = db.users.find(
    (u) =>
      u.email ===
      String(email || "")
        .trim()
        .toLowerCase()
  );
  if (
    !user ||
    !(await bcrypt.compare(String(password || ""), user.passwordHash))
  ) {
    return res.status(401).json({ error: "ایمیل یا رمز عبور اشتباه است." });
  }
  req.session.regenerate((err) => {
    if (err)
      return res.status(500).json({ error: "ورود انجام نشد. دوباره تلاش کن." });
    req.session.userId = user.id;
    res.json({
      message: "خوش آمدی!",
      user: publicUser(user),
      isAdmin: !!user.isAdmin,
    });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "خارج شدی." });
  });
});

app.post("/api/plan", requireAuth, (req, res) => {
  const allowed = ["TRAIN", "NUTRI", "COMBO", "AI PREMIUM"];
  const plan = String(req.body.plan || "").toUpperCase();
  if (!allowed.includes(plan))
    return res.status(400).json({ error: "پلن انتخابی معتبر نیست." });
  const db = readDB();
  const user = db.users.find((u) => u.id === req.user.id);
  user.plan = plan;
  writeDB(db);
  res.json({
    message: "انتخابت در حساب کاربری ذخیره شد. پرداخت آنلاین هنوز متصل نیست.",
    plan,
  });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(
      null,
      "certificate-" +
        Date.now() +
        "-" +
        Math.random().toString(36).slice(2, 7) +
        ext
    );
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.mimetype))
      return cb(new Error("فقط تصویر JPG، PNG یا WEBP مجاز است."));
    cb(null, true);
  },
});

app.get("/api/certificates", (req, res) => {
  const db = readDB();
  res.json({
    certificates: db.certificates.map((c) => ({
      id: c.id,
      title: c.title,
      filename: c.filename,
      url: "/uploads/" + c.filename,
      uploadedAt: c.uploadedAt,
    })),
  });
});
app.post(
  "/api/certificates",
  requireAdmin,
  upload.single("certificate"),
  (req, res) => {
    if (!req.file)
      return res.status(400).json({ error: "یک تصویر انتخاب کن." });
    const title = String(req.body.title || "مدرک مربی")
      .trim()
      .slice(0, 100);
    const db = readDB();
    const cert = {
      id: "c_" + Date.now(),
      title,
      filename: req.file.filename,
      uploadedAt: new Date().toISOString(),
    };
    db.certificates.push(cert);
    writeDB(db);
    res.json({
      message: "مدرک با موفقیت بارگذاری شد.",
      certificate: { ...cert, url: "/uploads/" + cert.filename },
    });
  }
);
app.delete("/api/certificates/:id", requireAdmin, (req, res) => {
  const db = readDB();
  const cert = db.certificates.find((c) => c.id === req.params.id);
  if (!cert) return res.status(404).json({ error: "مدرک پیدا نشد." });
  const file = path.join(UPLOAD_DIR, path.basename(cert.filename));
  if (fs.existsSync(file)) fs.unlinkSync(file);
  db.certificates = db.certificates.filter((c) => c.id !== cert.id);
  writeDB(db);
  res.json({ message: "مدرک حذف شد." });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const db = readDB();
  res.json({
    users: db.users.filter((u) => !u.isAdmin).length,
    certificates: db.certificates.length,
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(400).json({ error: err.message || "درخواست نامعتبر است." });
});

app.listen(PORT, () =>
  console.log(`TANPLUS is running at http://localhost:${PORT}`)
);
