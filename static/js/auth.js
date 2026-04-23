// static/js/auth.js
console.log("✅ auth.js loaded successfully");

// === FADE-IN ANIMATION ===
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".fade-in").forEach((el) => {
    requestAnimationFrame(() => el.classList.add("show"));
  });
});

// === LOGIN ===
function initLogin() {
  const form = document.getElementById("loginForm");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("loginUsername").value.trim();
    const password = document.getElementById("loginPassword").value.trim();

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();
      if (res.ok) {
        showToast("✅ Login successful!", "success");
        localStorage.setItem("user", JSON.stringify(data.profile));
        setTimeout(() => (window.location.href = "/profile"), 1000);
      } else {
        showToast("❌ " + data.error, "error");
      }
    } catch (err) {
      showToast("⚠️ Network error", "error");
    }
  });
}

// === REGISTER ===
function initRegister() {
  const form = document.getElementById("registerForm");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("regUsername").value.trim();
    const email = document.getElementById("regEmail").value.trim();
    const password = document.getElementById("regPassword").value.trim();

    // --- Client-side validation ---
    if (username.length < 3) {
      showToast("⚠️ Username must be at least 3 characters", "error");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showToast("⚠️ Enter a valid email", "error");
      return;
    }
    if (password.length < 6) {
      showToast("⚠️ Password must be at least 6 characters", "error");
      return;
    }

    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password }),
      });

      const data = await res.json();
      if (res.ok) {
        showToast("🎉 Registration successful! Redirecting...", "success");
        setTimeout(() => (window.location.href = "/login"), 1200);
      } else {
        showToast("❌ " + data.error, "error");
      }
    } catch (err) {
      showToast("⚠️ Network error", "error");
    }
  });
}
