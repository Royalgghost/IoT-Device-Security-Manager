"""
Report Generator Module
Prepares structured security audit reports, JSON exports,
and presentation data for printable audit reports.
"""

from datetime import datetime
from typing import Dict, Any

def generate_json_report(scan_results: Dict[str, Any], target_network: str = "") -> Dict[str, Any]:
    """Generates a comprehensive JSON export of the security assessment."""
    now = datetime.now()
    return {
        "report_metadata": {
            "title": "IoT Device Security & Vulnerability Assessment Report",
            "generated_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "target_network": target_network or "Local Network",
            "assessment_tool": "IoT Device Security Manager",
            "version": "1.0.0"
        },
        "executive_summary": {
            "overall_security_score": scan_results.get("security_score", 100),
            "posture_status": scan_results.get("score_status", "Good"),
            "total_devices_scanned": scan_results.get("total_devices", 0),
            "secure_devices": scan_results.get("secure_devices", 0),
            "vulnerability_breakdown": {
                "critical": scan_results.get("critical_count", 0),
                "high": scan_results.get("high_count", 0),
                "medium": scan_results.get("medium_count", 0),
                "low": scan_results.get("low_count", 0),
                "total": scan_results.get("total_vulnerabilities", 0)
            }
        },
        "device_inventory": scan_results.get("devices", []),
        "strategic_recommendations": scan_results.get("strategic_recommendations", [])
    }

def format_audit_summary(scan_results: Dict[str, Any], target_network: str = "") -> Dict[str, Any]:
    """Prepares structured data context for rendering report_template.html."""
    return generate_json_report(scan_results, target_network)
