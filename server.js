require("dotenv").config();
const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const helmet = require("helmet");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const csrf = require("csurf");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 3000;

// برای هاست‌هایی مثل Render لازم است
app.set("trust proxy", 1);

// دیتابیس SQLite
const db = new sqlite3.Database("./data.db");
db.serialize(() => {
  // جدول logs را با ستون‌های درست می‌سازد
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      info TEXT,
      result TEXT,
      time TEXT
    )
  `);
});

// امنیت پایه
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// سشن با ذخیره‌سازی در SQLite
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: "./" }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  }
}));

// CSRF
const csrfProtection = csrf({ cookie: false });

// فایل‌های استاتیک
app.use(express.static(path.join(__dirname, "public")));

// میدل‌ور برای محافظت از مسیرهای ادمین
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).send("Unauthorized");
}

// صفحه لاگین
app.get("/", csrfProtection, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// گرفتن توکن CSRF
app.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// لاگین
app.post("/login", csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  const isAdmin = username === process.env.ADMIN_USER;
  const match = isAdmin ? await bcrypt.compare(password, process.env.ADMIN_PASS_HASH) : false;

  const time = new Date().toLocaleString();
  const result = isAdmin && match ? "admin_login_success" : "login_failed";
  db.run("INSERT INTO logs (info, result, time) VALUES (?, ?, ?)", [`Login -> ${username}`, result, time]);

  if (isAdmin && match) {
    req.session.isAdmin = true;
    return res.redirect("/dashboard.html");
  } else {
    return res.redirect("https://copilot.microsoft.com/");
  }
});

// داشبورد
app.get("/dashboard.html", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// API: گرفتن داده‌ها
app.get("/data", requireAdmin, (req, res) => {
  db.all("SELECT * FROM logs ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ success: false });
    res.json(rows);
  });
});

// API: ذخیره داده جدید
app.post("/save", requireAdmin, csrfProtection, (req, res) => {
  const info = req.body.info || "";
  const time = new Date().toLocaleString();
  db.run("INSERT INTO logs (info, result, time) VALUES (?, ?, ?)", [info, "created", time], function (err) {
    if (err) return res.status(500).json({ success: false });
    db.all("SELECT * FROM logs ORDER BY id DESC", (err2, rows) => {
      if (err2) return res.status(500).json({ success: false });
      res.json({ success: true, data: rows });
    });
  });
});

// API: خروج
app.post("/logout", requireAdmin, csrfProtection, (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// اجرای سرور
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});