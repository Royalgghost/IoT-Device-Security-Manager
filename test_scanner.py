"""
Comprehensive Test Suite for IoT Device Security Manager
Verifies network detection, fingerprinting, vulnerability analysis,
mitigation generation, and Flask application endpoints.
"""

import unittest
import json
from app import app
from scanner import (
    get_local_network_info,
    DeviceFingerprinter,
    get_mock_iot_network,
    is_nmap_available
)
from analyzer import VulnerabilityEngine, MitigationGenerator
from reports import generate_json_report

class TestIoTDeviceSecurityManager(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        self.vuln_engine = VulnerabilityEngine()
        self.fingerprinter = DeviceFingerprinter()
        self.mitigation_gen = MitigationGenerator()

    def test_network_detector(self):
        """Verify network info detection returns valid IP and subnet."""
        info = get_local_network_info()
        self.assertIn("local_ip", info)
        self.assertIn("subnet_cidr", info)
        self.assertTrue(len(info["local_ip"].split(".")) == 4)

    def test_device_fingerprinting(self):
        """Verify fingerprinting categorizes devices accurately."""
        # Test IP Camera fingerprint
        cam_fp = self.fingerprinter.fingerprint_device(
            ip="192.168.1.105",
            mac="44:19:B6:00:00:00",
            ports=[80, 554, 3702],
            banners={554: "RTSP/1.0", 80: "Hikvision-Webs"}
        )
        self.assertEqual(cam_fp["device_type"], "IP Security Camera / DVR")
        self.assertEqual(cam_fp["confidence"], "High")

        # Test Smart Lock fingerprint
        lock_fp = self.fingerprinter.fingerprint_device(
            ip="192.168.1.142",
            mac="",
            ports=[23, 80],
            banners={23: "BusyBox ash"},
            hostname="smart-lock.local"
        )
        self.assertEqual(lock_fp["device_type"], "Smart Door Lock / Access Controller")

    def test_vulnerability_engine_and_scoring(self):
        """Verify vulnerability detection, CVSS calculation, and network scoring."""
        mock_devices = get_mock_iot_network()
        self.assertGreater(len(mock_devices), 0)

        results = self.vuln_engine.analyze_network(mock_devices)
        self.assertIn("security_score", results)
        self.assertIn("critical_count", results)
        self.assertIn("high_count", results)
        self.assertGreater(results["critical_count"], 0)
        self.assertLessEqual(results["security_score"], 100)

        # Check camera device vulnerabilities
        cam_device = next(d for d in results["devices"] if d["ip"] == "192.168.1.105")
        vuln_ids = [v["id"] for v in cam_device["vulnerabilities"]]
        self.assertIn("IOT-VULN-003", vuln_ids) # RTSP
        self.assertIn("IOT-VULN-005", vuln_ids) # Hikvision CVE

    def test_mitigation_generator(self):
        """Verify mitigation steps are populated with steps and priority."""
        mit = self.mitigation_gen.get_mitigation_for_vuln("IOT-VULN-001")
        self.assertIn("steps", mit)
        self.assertGreater(len(mit["steps"]), 0)
        self.assertIn("P0", mit["priority"])

    def test_report_generator(self):
        """Verify report generator produces valid audit structure."""
        mock_devices = get_mock_iot_network()
        results = self.vuln_engine.analyze_network(mock_devices)
        report = generate_json_report(results, "192.168.1.0/24")
        self.assertIn("executive_summary", report)
        self.assertIn("device_inventory", report)
        self.assertEqual(report["executive_summary"]["total_devices_scanned"], len(mock_devices))

    def test_flask_routes(self):
        """Verify web application routes and API endpoints."""
        # Dashboard
        res = self.app.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"IoT Security Manager", res.data)

        # Network Info API
        res = self.app.get("/api/network-info")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("network", data)

        # Scan Status API
        res = self.app.get("/api/scan/status")
        self.assertEqual(res.status_code, 200)

        # Devices API
        res = self.app.get("/api/devices")
        self.assertEqual(res.status_code, 200)

        # Device Detail Page
        res = self.app.get("/device/192.168.1.105")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"192.168.1.105", res.data)

        # Remediation Page
        res = self.app.get("/mitigations")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Remediation Roadmap", res.data)

        # Printable Report Page
        res = self.app.get("/report")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Audit Report", res.data)

        # Export JSON API
        res = self.app.get("/api/export/json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.content_type, "application/json")

if __name__ == "__main__":
    unittest.main()
