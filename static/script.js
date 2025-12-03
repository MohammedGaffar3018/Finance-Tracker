document.addEventListener('DOMContentLoaded', function () {
    // Fetch data for charts
    fetch('/api/data')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('expenseChart').getContext('2d');

            if (data.categories.length > 0) {
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: data.categories,
                        datasets: [{
                            data: data.category_data,
                            backgroundColor: [
                                '#ff7675',
                                '#74b9ff',
                                '#55efc4',
                                '#a29bfe',
                                '#fd79a8',
                                '#ffeaa7'
                            ],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    color: 'white'
                                }
                            }
                        }
                    }
                });
            } else {
                // Show placeholder or empty state if no data
                ctx.font = "14px Arial";
                ctx.fillStyle = "white";
                ctx.textAlign = "center";
                ctx.fillText("No expenses yet", ctx.canvas.width / 2, ctx.canvas.height / 2);
            }
        })
        .catch(error => console.error('Error fetching data:', error));
});
