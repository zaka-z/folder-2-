const form = document.getElementById("dataForm");
const dataList = document.getElementById("dataList");
const logoutForm = document.getElementById("logoutForm");

async function getCsrf() {
  const res = await fetch("/csrf-token", { credentials: "same-origin" });
  const { csrfToken } = await res.json();
  // ست برای فرم‌های مختلف
  const csrfData = document.getElementById("csrfData");
  const csrfLogout = document.getElementById("csrfLogout");
  if (csrfData) csrfData.value = csrfToken;
  if (csrfLogout) csrfLogout.value = csrfToken;
  return csrfToken;
}

function escapeHTML(str) {
  return str.replace(/[&<>"']/g, s => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[s]));
}

async function fetchData() {
  const res = await fetch("/data", { credentials: "same-origin" });
  const data = await res.json();
  renderData(data);
}

function renderData(data) {
  dataList.innerHTML = "";
  data.forEach(item => {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.innerHTML = `${escapeHTML(item.info)} <small style="color:#666">(${escapeHTML(item.time || "")})</small>`;

    const actions = document.createElement("div");
    actions.className = "actions";

    const editBtn = document.createElement("button");
    editBtn.className = "edit-btn";
    editBtn.textContent = "✏️ ویرایش";
    editBtn.onclick = async () => {
      const current = item.info.replace(/^Edited:\s*/,'').replace(/^Info:\s*/,'');
      const newInfo = prompt("اطلاعات جدید را وارد کنید:", current);
      if (newInfo !== null) {
        const csrfToken = await getCsrf();
        const res = await fetch(`/edit/${item.id}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "CSRF-Token": csrfToken
          },
          credentials: "same-origin",
          body: JSON.stringify({ newInfo })
        });
        const result = await res.json();
        if (result.success) renderData(result.data);
      }
    };

    const delBtn = document.createElement("button");
    delBtn.className = "delete-btn";
    delBtn.textContent = "❌ حذف";
    delBtn.onclick = async () => {
      if (!confirm("آیا از حذف مطمئن هستید؟")) return;
      const csrfToken = await getCsrf();
      const res = await fetch(`/delete/${item.id}`, {
        method: "DELETE",
        headers: { "CSRF-Token": csrfToken },
        credentials: "same-origin"
      });
      const result = await res.json();
      if (result.success) renderData(result.data);
    };

    actions.appendChild(editBtn);
    actions.appendChild(delBtn);
    li.appendChild(span);
    li.appendChild(actions);
    dataList.appendChild(li);
  });
}

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const info = document.getElementById("info").value.trim();
    if (!info) return;

    const csrfToken = await getCsrf();
    const res = await fetch("/save", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CSRF-Token": csrfToken
      },
      credentials: "same-origin",
      body: JSON.stringify({ info })
    });

    const result = await res.json();
    if (result.success) {
      renderData(result.data);
      document.getElementById("info").value = "";
    }
  });

  window.onload = async () => {
    await getCsrf();
    await fetchData();
  };
}

if (logoutForm) {
  logoutForm.addEventListener("submit", async (e) => {
    // CSRF قبلاً ست شده؛ فقط اجازه ارسال بده
  });
}