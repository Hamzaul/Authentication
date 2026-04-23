document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("resetForm");
  const msg = document.getElementById("resetMsg");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const password = document.getElementById("newPassword").value;
    const token = document.getElementById("resetToken").value;

    try {
      const res = await fetch("http://127.0.0.1:5000/api/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });

      const data = await res.json();
      msg.textContent = data.message || data.error;
      msg.style.color = data.message ? "lightgreen" : "red";
    } catch (err) {
      msg.textContent = "Something went wrong.";
      msg.style.color = "red";
      console.error(err);
    }
  });
});
