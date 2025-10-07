// frontend/js/chart.js

fetch('http://localhost:8000/results')
  .then(res => res.json())
  .then(data => {
    const ctx = document.getElementById('threatChart');
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: Object.keys(data.stats),
        datasets: [{
          data: Object.values(data.stats),
          backgroundColor: ['#00d4ff', '#ff3366', '#00ff88'],
        }]
      },
      options: {
        plugins: {
          legend: {
            labels: { color: '#e0e0e0' }
          }
        }
      }
    });

    const tbody = document.querySelector('#threatTable tbody');
    data.threats.forEach(t => {
      tbody.innerHTML += `
        <tr>
          <td>${t.timestamp}</td>
          <td>${t.ip}</td>
          <td>${t.type}</td>
          <td style="color:${t.severity === 'High' ? '#ff3366' : '#00ff88'}">
            ${t.severity}
          </td>
        </tr>`;
    });
  })
  .catch(err => console.error("Error loading chart:", err));
