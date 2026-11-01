/**
 * Chart.js Visualizations for Security Dashboard
 */

document.addEventListener("DOMContentLoaded", () => {
    if (typeof INITIAL_CHART_DATA === "undefined") return;

    const sevData = INITIAL_CHART_DATA.severities || {};
    const catData = INITIAL_CHART_DATA.categories || {};

    // 1. Vulnerability Severity Doughnut Chart
    const ctxSev = document.getElementById("vulnSeverityChart");
    if (ctxSev) {
        new Chart(ctxSev, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low", "Hardened"],
                datasets: [{
                    data: [
                        sevData.critical || 0,
                        sevData.high || 0,
                        sevData.medium || 0,
                        sevData.low || 0,
                        sevData.secure || 0
                    ],
                    backgroundColor: [
                        "#ef4444", // Critical Red
                        "#f59e0b", // High Amber
                        "#3b82f6", // Medium Blue
                        "#64748b", // Low Slate
                        "#10b981"  // Hardened Emerald
                    ],
                    borderColor: "#0f172a",
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "right",
                        labels: {
                            color: "#94a3b8",
                            font: { family: "Inter", size: 12 },
                            boxWidth: 12,
                            padding: 10
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return ` ${context.label}: ${context.raw} item(s)`;
                            }
                        }
                    }
                },
                cutout: "70%"
            }
        });
    }

    // 2. Device Category Bar Chart
    const ctxCat = document.getElementById("deviceCategoryChart");
    if (ctxCat) {
        const catLabels = Object.keys(catData);
        const catCounts = Object.values(catData);

        new Chart(ctxCat, {
            type: "bar",
            data: {
                labels: catLabels.length ? catLabels : ["No Devices Discovered"],
                datasets: [{
                    label: "Count",
                    data: catCounts.length ? catCounts : [0],
                    backgroundColor: "rgba(16, 185, 129, 0.35)",
                    borderColor: "#10b981",
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y", // horizontal bar
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: {
                            color: "#94a3b8",
                            font: { family: "Inter", size: 11 },
                            stepSize: 1
                        },
                        grid: { color: "rgba(148, 163, 184, 0.1)" }
                    },
                    y: {
                        ticks: {
                            color: "#f8fafc",
                            font: { family: "Inter", size: 11 }
                        },
                        grid: { display: false }
                    }
                }
            }
        });
    }
});
