// frontend/js/main.js

const form = document.getElementById("uploadForm");
const progress = document.getElementById("progressBar");
const output = document.getElementById("output");

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const file = document.getElementById("logFile").files[0];
  if (!file) return alert("Please select a file first!");

  progress.style.width = "30%";
  output.innerHTML = "<p>🔎 Scanning file... please wait.</p>";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch("http://localhost:8000/upload", {
      method: "POST",
      body: formData,
    });

    progress.style.width = "70%";
    const data = await response.json();
    progress.style.width = "100%";

    if (data.error) {
      output.innerHTML = `<p style='color:red;'>❌ ${data.error}</p>`;
      return;
    }

    const color = data.prediction === "Malicious" ? "red" : "green";
    output.innerHTML = `
      <div style="border:2px solid ${color}; padding:15px; border-radius:10px;">
        <h3>📄 File: ${data.filename}</h3>
        <p><strong>Result:</strong> ${data.prediction}</p>
        <p><strong>Confidence:</strong> ${data.confidence}%</p>
        <p>${data.message}</p>
      </div>
    `;
  } catch (error) {
    output.innerHTML = "<p style='color:red;'>❌ Error analyzing file.</p>";
    console.error(error);
  }
});
