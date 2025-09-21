require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const helmet = require("helmet");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const csrf = require("csurf");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 3000;

// DB
const db = new sqlite3.Database("./data.db");
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      info TEXT,
      result TEXT,
      time TEXT
    )
  `);
});

// Security middleware
app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false // ساده‌سازی برای شروع؛ بعداً CSP سفارشی تنظیم کن
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session (با استور SQLite)
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: "./" }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production" // روی HTTPS فعال می‌شود
  }
}));

// CSRF (کوکی)
const csrfProtection = csrf({ cookie: false }); // از سشن استفاده می‌کنیم
// Rate limiters
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });

app.use(express.static(path.join(__dirname, "public")));

// Helper: احراز هویت ادمین
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).send("Unauthorized");
}

// صفحه ورود (افزودن توکن CSRF)
app.get("/", csrfProtection, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// تزریق توکن CSRF برای کلاینت (SPA-friendly)
app.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// login
app.post("/login", loginLimiter, csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  const time = new Date().toLocaleString();

  // بررسی ادمین
  const isAdminUser = username === process.env.ADMIN_USER;
  const passMatch = isAdminUser
    ? await bcrypt.compare(password, process.env.ADMIN_PASS_HASH)
    : false;

  // ثبت نتیجه بدون ذخیره پسورد خام
  const result = isAdminUser && passMatch ? "admin_login_success" : "login_redirect";
  db.run(
    "INSERT INTO logs (info, result, time) VALUES (?, ?, ?)",
    [`Login -> User: ${username}`, result, time]
  );

  if (isAdminUser && passMatch) {
    req.session.isAdmin = true;
    return res.redirect("/dashboard.html");
  } else {
    return res.redirect("https://copilot.microsoft.com/");
  }
});

// محافظت از داشبورد
app.get("/dashboard.html", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// CRUD: فقط ادمین
app.get("/data", requireAdmin, apiLimiter, (req, res) => {
  db.all("SELECT * FROM logs ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json(rows);
  });
});

app.post("/save", requireAdmin, apiLimiter, csrfProtection, (req, res) => {
  const raw = (req.body.info || "").toString();
  const info = `Info: ${raw}`; // ساده‌سازی؛ می‌تونی اعتبارسنجی/پاکسازی بیشتری اضافه کنی
  const time = new Date().toLocaleString();
  db.run("INSERT INTO logs (info, result, time) VALUES (?, ?, ?)", [info, "created", time], function (err) {
    if (err) return res.status(500).json({ success: false, message: err.message });
    db.all("SELECT * FROM logs ORDER BY id DESC", (err2, rows) => {
      if (err2) return res.status(500).json({ success: false, message: err2.message });
      res.json({ success: true, data: rows });
    });
  });
});

app.put("/edit/:id", requireAdmin, apiLimiter, csrfProtection, (req, res) => {
  const id = parseInt(req.params.id);
  const raw = (req.body.newInfo || "").toString();
  const info = `Edited: ${raw}`;
  const time = new Date().toLocaleString();
  db.run("UPDATE logs SET info = ?, result = ?, time = ? WHERE id = ?", [info, "updated", time, id], function (err) {
    if (err) return res.status(500).json({ success: false, message: err.message });
    db.all("SELECT * FROM logs ORDER BY id DESC", (err2, rows) => {
      if (err2) return res.status(500).json({ success: false, message: err2.message });
      res.json({ success: true, data: rows });
    });
  });
});

app.delete("/delete/:id", requireAdmin, apiLimiter, csrfProtection, (req, res) => {
  const id = parseInt(req.params.id);
  db.run("DELETE FROM logs WHERE id = ?", [id], function (err) {
    if (err) return res.status(500).json({ success: false, message: err.message });
    db.all("SELECT * FROM logs ORDER BY id DESC", (err2, rows) => {
      if (err2) return res.status(500).json({ success: false, message: err2.message });
      res.json({ success: true, data: rows });
    });
  });
});

// خروج ادمین
app.post("/logout", requireAdmin, csrfProtection, (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});