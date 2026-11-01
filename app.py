"""
IoT Device Security Manager - Flask Web Application
Main application controller handling routes, background scanning,
API endpoints, and template rendering.
"""

import os
import threading
import time
from flask import Flask, render_template, request, jsonify, Response, send_file, redirect, url_for
from config import Config
from scanner import (
    get_local_network_info,
    SocketScanner,
    NmapScanner,
    is_nmap_available,
    get_mock_iot_network
)
from analyzer import VulnerabilityEngine
from reports import generate_json_report, format_audit_summary
import json
import io

app = Flask(__name__)
app.config.from_object(Config)

# Shared in-memory scan state with thread safety
scan_lock = threading.Lock()
current_scan_state = {
    "is_scanning": False,
    "progress": 0,
    "status_message": "Ready to scan network",
    "logs": [],
    "target": "",
    "mode": "auto",
    "last_completed_at": None,
    "results": None
}

vuln_engine = VulnerabilityEngine()

# Initialize with mock lab data so the dashboard is immediately populated and informative on first launch!
initial_mock_devices = get_mock_iot_network()
current_scan_state["results"] = vuln_engine.analyze_network(initial_mock_devices)
current_scan_state["target"] = "192.168.1.0/24 (Simulated Lab)"
current_scan_state["status_message"] = "Demonstration environment loaded. Ready for live network scan."

def update_scan_progress(percent: int, total: int, message: str):
    """Callback to update scan state and append log entry."""
    with scan_lock:
        current_scan_state["progress"] = min(100, max(0, percent))
        current_scan_state["status_message"] = message
        timestamp = time.strftime("%H:%M:%S")
        current_scan_state["logs"].append(f"[{timestamp}] {message}")
        if len(current_scan_state["logs"]) > 200:
            current_scan_state["logs"].pop(0)

def execute_network_scan(target: str, mode: str):
    """Background worker function executing the scan."""
    global current_scan_state
    try:
        with scan_lock:
            current_scan_state["is_scanning"] = True
            current_scan_state["progress"] = 2
            current_scan_state["status_message"] = f"Initializing {mode.upper()} scan on {target}..."
            current_scan_state["logs"] = [f"[{time.strftime('%H:%M:%S')}] Scan initiated for target: {target} (Mode: {mode})"]
            current_scan_state["target"] = target
            current_scan_state["mode"] = mode

        discovered = []

        if mode == "demo" or target == "demo-lab":
            update_scan_progress(15, 100, "Starting Virtual IoT Lab simulation...")
            time.sleep(0.5)
            update_scan_progress(35, 100, "Probing simulated IP Security Cameras & Smart Deadbolts...")
            time.sleep(0.6)
            update_scan_progress(60, 100, "Probing simulated MQTT Home Hubs & SCADA Modbus PLC...")
            time.sleep(0.5)
            update_scan_progress(80, 100, "Probing Smart TV SSDP services & Gateway Routers...")
            time.sleep(0.4)
            discovered = get_mock_iot_network()
        
        elif mode == "nmap":
            nmap_ok, path = is_nmap_available()
            if not nmap_ok:
                update_scan_progress(10, 100, "Nmap binary not found. Falling back to High-Speed Socket Scanner...")
                socket_scanner = SocketScanner()
                discovered = socket_scanner.scan_network(target, progress_callback=update_scan_progress)
            else:
                nmap_scanner = NmapScanner()
                discovered = nmap_scanner.scan_network(target, progress_callback=update_scan_progress)

        else:  # socket or auto
            socket_scanner = SocketScanner()
            discovered = socket_scanner.scan_network(target, progress_callback=update_scan_progress)

        update_scan_progress(90, 100, "Correlating open ports against IoT CVE database & generating mitigations...")
        time.sleep(0.3)
        analyzed_results = vuln_engine.analyze_network(discovered)

        with scan_lock:
            current_scan_state["results"] = analyzed_results
            current_scan_state["progress"] = 100
            current_scan_state["is_scanning"] = False
            current_scan_state["status_message"] = f"Scan complete! Discovered {analyzed_results['total_devices']} device(s)."
            current_scan_state["last_completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            current_scan_state["logs"].append(f"[{time.strftime('%H:%M:%S')}] Assessment completed. Security Score: {analyzed_results['security_score']}/100.")

    except Exception as e:
        with scan_lock:
            current_scan_state["is_scanning"] = False
            current_scan_state["progress"] = 0
            current_scan_state["status_message"] = f"Scan error: {str(e)}"
            current_scan_state["logs"].append(f"[{time.strftime('%H:%M:%S')}] ERROR: {str(e)}")

# ==================== WEB ROUTES ====================

@app.route("/")
def index():
    """Main dashboard page."""
    net_info = get_local_network_info()
    nmap_ok, nmap_path = is_nmap_available()
    results = current_scan_state.get("results") or {
        "devices": [],
        "total_devices": 0,
        "security_score": 100,
        "score_status": "Ready",
        "score_color": "#10b981",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "device_categories": {}
    }
    return render_template(
        "index.html",
        net_info=net_info,
        nmap_available=nmap_ok,
        nmap_path=nmap_path,
        scan_state=current_scan_state,
        results=results
    )

@app.route("/device/<ip>")
def device_detail(ip):
    """Detailed view for an individual IoT device."""
    results = current_scan_state.get("results", {})
    devices = results.get("devices", [])
    device = next((d for d in devices if d.get("ip") == ip), None)
    if not device:
        return redirect(url_for("index"))
    return render_template("device_detail.html", device=device, scan_target=current_scan_state.get("target"))

@app.route("/mitigations")
def mitigations_view():
    """Consolidated remediation checklist and network hardening guidance."""
    results = current_scan_state.get("results", {})
    return render_template("mitigations.html", results=results, scan_target=current_scan_state.get("target"))

@app.route("/report")
def audit_report():
    """Printable executive security audit report."""
    results = current_scan_state.get("results", {})
    target = current_scan_state.get("target", "Local Network")
    report_data = format_audit_summary(results, target)
    return render_template("report_template.html", report=report_data)

# ==================== API ENDPOINTS ====================

@app.route("/api/network-info")
def api_network_info():
    """Returns detected network details and tool availability."""
    net_info = get_local_network_info()
    nmap_ok, nmap_path = is_nmap_available()
    return jsonify({
        "network": net_info,
        "nmap": {
            "available": nmap_ok,
            "path": nmap_path
        }
    })

@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    """Starts a new background network scan."""
    with scan_lock:
        if current_scan_state["is_scanning"]:
            return jsonify({"status": "error", "message": "A scan is already currently running."}), 400

    data = request.get_json() or {}
    target = data.get("target", "").strip()
    mode = data.get("mode", "socket").strip().lower()

    if not target:
        net_info = get_local_network_info()
        target = net_info.get("subnet_cidr", "127.0.0.1")

    # Launch background thread
    t = threading.Thread(target=execute_network_scan, args=(target, mode), daemon=True)
    t.start()

    return jsonify({
        "status": "started",
        "target": target,
        "mode": mode,
        "message": f"Scan initiated on {target}"
    })

@app.route("/api/scan/status")
def api_scan_status():
    """Polls real-time progress and logs."""
    with scan_lock:
        return jsonify({
            "is_scanning": current_scan_state["is_scanning"],
            "progress": current_scan_state["progress"],
            "status_message": current_scan_state["status_message"],
            "logs": current_scan_state["logs"][-20:],
            "target": current_scan_state["target"],
            "mode": current_scan_state["mode"],
            "last_completed_at": current_scan_state["last_completed_at"]
        })

@app.route("/api/devices")
def api_get_devices():
    """Returns latest scanned devices and metrics."""
    with scan_lock:
        results = current_scan_state.get("results", {})
        return jsonify(results)

@app.route("/api/export/json")
def api_export_json():
    """Downloads assessment report as JSON."""
    with scan_lock:
        results = current_scan_state.get("results", {})
        target = current_scan_state.get("target", "Local Network")
    report = generate_json_report(results, target)
    json_bytes = json.dumps(report, indent=2).encode('utf-8')
    buffer = io.BytesIO(json_bytes)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"iot-security-audit-{time.strftime('%Y%m%d-%H%M%S')}.json",
        mimetype="application/json"
    )

if __name__ == "__main__":
    print("Starting IoT Device Security Manager on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
