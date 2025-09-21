// گرفتن توکن CSRF و ست کردن در فرم‌ها
async function getCsrf() {
  try {
    const res = await fetch("/csrf-token", { credentials: "same-origin" });
    const { csrfToken } = await res.json();
    document.getElementById("csrfData").value = csrfToken;
    document.getElementById("csrfLogout").value = csrfToken;
    return csrfToken;
  } catch (err) {
    console.error("خطا در گرفتن CSRF:", err);
  }
}

// جلوگیری از XSS
function escapeHTML(str) {
  return str.replace(/[&<>"']/g, s => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[s]));
}

// گرفتن داده‌ها از سرور و نمایش در لیست
async function fetchData() {
  try {
    const res = await fetch("/data", { credentials: "same-origin" });
    if (!res.ok) throw new Error("خطا در دریافت داده‌ها");
    const data = await res.json();
    const list = document.getElementById("dataList");
    list.innerHTML = "";
    data.forEach(item => {
      const li = document.createElement("li");
      li.textContent = `${item.id}: ${escapeHTML(item.info)} (${item.time})`;
      list.appendChild(li);
    });
  } catch (err) {
    console.error("خطا در fetchData:", err);
  }
}

// ذخیره داده جدید
document.getElementById("dataForm").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const info = document.getElementById("info").value;
    const csrf = document.getElementById("csrfData").value;
    const res = await fetch("/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ info, _csrf: csrf })
    });
    const result = await res.json();
    if (result.success) {
      document.getElementById("info").value = "";
      fetchData();
    } else {
      console.error("ذخیره ناموفق:", result);
    }
  } catch (err) {
    console.error("خطا در ذخیره:", err);
  }
});

// شروع: گرفتن CSRF و سپس گرفتن داده‌ها
getCsrf().then(fetchData);