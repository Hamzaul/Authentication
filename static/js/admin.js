// static/js/admin.js
document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("adminLoginForm");
  const dashboard = document.getElementById("adminDashboard");
  const msg = document.getElementById("adminMsg");
  const usersDiv = document.getElementById("adminUsers");

  // Settings dropdown
  const settings = document.getElementById("settings");
  const gearBtn = document.getElementById("gearBtn");
  const logoutBtn = document.getElementById("adminLogoutBtn");

  // ====== Admin Login ======
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    msg.textContent = "Logging in...";

    const username = document.getElementById("adminUsername").value.trim();
    const password = document.getElementById("adminPassword").value;

    try {
      const res = await fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "Login failed");

      msg.textContent = "";
      loginForm.classList.add("hidden");
      dashboard.classList.remove("hidden");
      dashboard.classList.add("show");

      await loadUsers();
    } catch (err) {
      msg.textContent = "Error: " + err.message;
    }
  });

  // ====== Settings dropdown ======
  gearBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = settings.classList.toggle("open");
    gearBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
  });

  document.addEventListener("click", (e) => {
    if (!settings.contains(e.target)) {
      settings.classList.remove("open");
      gearBtn.setAttribute("aria-expanded", "false");
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      settings.classList.remove("open");
      gearBtn.setAttribute("aria-expanded", "false");
    }
  });

  // ====== Admin Logout ======
  logoutBtn.addEventListener("click", async () => {
    try {
      await fetch("/api/admin/logout", { method: "POST" });
    } catch (_) {}
    settings.classList.remove("open");
    dashboard.classList.add("hidden");
    loginForm.classList.remove("hidden");
    msg.textContent = "Logged out.";
    usersDiv.innerHTML = "";
    document.getElementById("adminPassword").value = "";
  });

  // ====== Load Users ======
  async function loadUsers() {
    usersDiv.innerHTML = "<p class='muted'>Loading users…</p>";
    try {
      const res = await fetch("/api/admin/users");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Unable to load users");

      if (!data.users || !data.users.length) {
        usersDiv.innerHTML = "<p class='muted'>No users found.</p>";
        return;
      }

      const table = document.createElement("table");
      table.innerHTML = `
        <thead>
          <tr>
            <th style="width:64px">#</th>
            <th>Username</th>
            <th>Email</th>
            <th>User ID</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody></tbody>
      `;

      const tbody = table.querySelector("tbody");

      data.users.forEach((u, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${idx + 1}</td>
          <td>${escapeHtml(u.username || "-")}</td>
          <td>${escapeHtml(u.email || "-")}</td>
          <td class="mono">${escapeHtml(u._id)}</td>
          <td>
            <button class="btn danger remove-user" data-id="${u._id}">➖ Remove</button>
          </td>
        `;
        tbody.appendChild(tr);
      });

      usersDiv.innerHTML = "";
      usersDiv.appendChild(table);

      // Attach delete handlers
      document.querySelectorAll(".remove-user").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const userId = btn.dataset.id;
          if (!confirm("Are you sure you want to delete this user?")) return;

          try {
            const res = await fetch("/api/admin/delete-user", {
              method: "DELETE",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ user_id: userId })
            });
            const data = await res.json();

            if (!res.ok) throw new Error(data.error || "Failed to delete user");

            alert(`✅ ${data.message}`);
            await loadUsers(); // Refresh table
          } catch (err) {
            alert("❌ " + err.message);
          }
        });
      });

    } catch (err) {
      usersDiv.innerHTML = `<p class='msg'>Error: ${err.message}</p>`;
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }
});
