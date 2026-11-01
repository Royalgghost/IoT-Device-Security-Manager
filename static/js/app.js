/**
 * IoT Device Security Manager - Frontend Controller
 * Handles scan dispatching, live progress polling, search filtering, and UI updates.
 */

document.addEventListener("DOMContentLoaded", () => {
    const btnStartScan = document.getElementById("btnStartScan");
    const btnDemoLab = document.getElementById("btnDemoLab");
    const targetInput = document.getElementById("targetInput");
    const scanModeSelect = document.getElementById("scanModeSelect");
    const scanProgressCard = document.getElementById("scanProgressCard");
    const scanProgressBar = document.getElementById("scanProgressBar");
    const scanStatusText = document.getElementById("scanStatusText");
    const scanPercentText = document.getElementById("scanPercentText");
    const scanTerminalLogs = document.getElementById("scanTerminalLogs");
    const deviceSearchInput = document.getElementById("deviceSearchInput");
    const severityFilter = document.getElementById("severityFilter");

    let pollInterval = null;

    // Preset options in dropdown
    document.querySelectorAll(".preset-option").forEach(el => {
        el.addEventListener("click", (e) => {
            e.preventDefault();
            const val = el.dataset.target;
            if (val === "demo-lab") {
                targetInput.value = "192.168.1.0/24 (Virtual Lab)";
                scanModeSelect.value = "demo";
            } else {
                targetInput.value = val;
            }
        });
    });

    // Start Scan handler
    async function startScan(target, mode) {
        if (!target) {
            alert("Please enter a target IP or subnet CIDR.");
            return;
        }

        btnStartScan.disabled = true;
        btnDemoLab.disabled = true;
        scanProgressCard.style.display = "block";
        scanProgressBar.style.width = "5%";
        scanPercentText.innerText = "5%";
        scanStatusText.innerText = `Dispatching scan on ${target}...`;

        try {
            const resp = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target: target, mode: mode })
            });
            const data = await resp.json();

            if (!resp.ok) {
                alert(data.message || "Failed to start scan");
                btnStartScan.disabled = false;
                btnDemoLab.disabled = false;
                return;
            }

            // Start polling status
            startPollingStatus();
        } catch (err) {
            console.error("Scan dispatch error:", err);
            btnStartScan.disabled = false;
            btnDemoLab.disabled = false;
        }
    }

    btnStartScan.addEventListener("click", () => {
        const target = targetInput.value.trim();
        const mode = scanModeSelect.value;
        startScan(target, mode);
    });

    btnDemoLab.addEventListener("click", () => {
        targetInput.value = "192.168.1.0/24 (Virtual Lab)";
        scanModeSelect.value = "demo";
        startScan("demo-lab", "demo");
    });

    // Status polling
    function startPollingStatus() {
        if (pollInterval) clearInterval(pollInterval);

        pollInterval = setInterval(async () => {
            try {
                const resp = await fetch("/api/scan/status");
                const status = await resp.json();

                scanProgressBar.style.width = `${status.progress}%`;
                scanPercentText.innerText = `${status.progress}%`;
                scanStatusText.innerText = status.status_message;

                // Update terminal logs
                if (status.logs && scanTerminalLogs) {
                    scanTerminalLogs.innerHTML = status.logs.map(l => `<div>${l}</div>`).join("");
                    scanTerminalLogs.scrollTop = scanTerminalLogs.scrollHeight;
                }

                if (!status.is_scanning) {
                    clearInterval(pollInterval);
                    btnStartScan.disabled = false;
                    btnDemoLab.disabled = false;
                    // Reload to update dashboard stats, charts, and device list
                    setTimeout(() => {
                        window.location.reload();
                    }, 1200);
                }
            } catch (err) {
                console.error("Status poll error:", err);
            }
        }, 1200);
    }

    // Client-side search and filtering for Discovered Devices
    function filterDeviceTable() {
        const query = (deviceSearchInput?.value || "").toLowerCase().trim();
        const selectedSeverity = severityFilter?.value || "ALL";
        const rows = document.querySelectorAll(".device-row");

        rows.forEach(row => {
            const rowSearch = (row.dataset.search || "").toLowerCase();
            const rowSeverity = (row.dataset.severity || "").toUpperCase();

            const matchesQuery = !query || rowSearch.includes(query);
            const matchesSeverity = (selectedSeverity === "ALL") || (rowSeverity === selectedSeverity);

            if (matchesQuery && matchesSeverity) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        });
    }

    deviceSearchInput?.addEventListener("input", filterDeviceTable);
    severityFilter?.addEventListener("change", filterDeviceTable);
});
