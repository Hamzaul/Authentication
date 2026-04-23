document.addEventListener("DOMContentLoaded", () => {
  const user = JSON.parse(localStorage.getItem("user"));

  if (!user) {
    document.getElementById("profileUsername").textContent = "Not logged in";
    document.getElementById("profileEmail").textContent = "-";
    return;
  }

  document.getElementById("profileUsername").textContent = user.username;
  document.getElementById("profileEmail").textContent = user.email;

  // Logout
  document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.clear();
    window.location.href = "/login";
  });
});
