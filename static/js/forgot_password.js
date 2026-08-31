document.getElementById("forgotForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("forgotEmail").value;

  try {
    const res = await fetch("http://127.0.0.1:5000/api/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    });

    const data = await res.json();
    document.getElementById("forgotMsg").textContent =
      data.message || data.error;
  } catch (err) {
    console.error(err);
  }
});
