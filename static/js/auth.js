// static/js/auth.js
console.log("✅ auth.js loaded successfully");
 
// === FADE-IN ANIMATION ===
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".fade-in").forEach((el) => {
    requestAnimationFrame(() => el.classList.add("show"));
  });
});
 
// === TOAST HELPER (in case not defined elsewhere) ===
function showToast(message, type = "success") {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();
 
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    padding: 12px 20px; border-radius: 8px; font-size: 14px;
    color: #fff; opacity: 0; transition: opacity 0.3s;
    background: ${type === "success" ? "#22c55e" : "#ef4444"};
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
  `;
  document.body.appendChild(toast);
  requestAnimationFrame(() => (toast.style.opacity = "1"));
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
 
// === BUTTON LOADING STATE ===
function setLoading(btn, loading) {
  if (!btn) return;
  btn.disabled = loading;
  btn.dataset.originalText = btn.dataset.originalText || btn.textContent;
  btn.textContent = loading ? "Please wait..." : btn.dataset.originalText;
}
 
// === LOGIN ===
function initLogin() {
  const form = document.getElementById("loginForm");
  if (!form) return;
 
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = form.querySelector("button[type=submit]");
 
    // ⚠️ Do NOT trim password — spaces are valid characters
    const username = document.getElementById("loginUsername").value.trim();
    const password = document.getElementById("loginPassword").value;
 
    if (!username || !password) {
      showToast("⚠️ Please fill in all fields", "error");
      return;
    }
 
    setLoading(btn, true);
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // needed for session cookie (admin)
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
      showToast("⚠️ Network error. Please try again.", "error");
    } finally {
      setLoading(btn, false);
    }
  });
}
 
// === REGISTER ===
function initRegister() {
  const form = document.getElementById("registerForm");
  if (!form) return;
 
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = form.querySelector("button[type=submit]");
 
    const username = document.getElementById("regUsername").value.trim();
    const email    = document.getElementById("regEmail").value.trim();
    // ⚠️ Do NOT trim password
    const password = document.getElementById("regPassword").value;
 
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
 
    setLoading(btn, true);
    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password }),
      });
 
      const data = await res.json();
      if (res.ok) {
        // ✅ Don't redirect to login — user must verify email first
        showToast("🎉 Registered! Please check your email to verify your account.", "success");
        form.reset();
      } else {
        showToast("❌ " + data.error, "error");
      }
    } catch (err) {
      showToast("⚠️ Network error. Please try again.", "error");
    } finally {
      setLoading(btn, false);
    }
  });
}