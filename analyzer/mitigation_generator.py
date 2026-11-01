"""
Mitigation Steps Generator
Produces structured, actionable, step-by-step remediation instructions,
CLI/configuration commands, and network hardening strategies for identified IoT vulnerabilities.
"""

from typing import Dict, Any, List

MITIGATION_PLANS = {
    "IOT-VULN-001": {
        "title": "Remediate Telnet Cleartext Protocol",
        "priority": "P0 - Immediate Action",
        "summary": "Disable legacy Telnet service and switch exclusively to encrypted SSH with key-based authentication.",
        "steps": [
            "Log into the device's web management interface via browser.",
            "Navigate to Network Settings > Advanced Services > Remote Management.",
            "Toggle Telnet service to 'Disabled' or 'Off'.",
            "If remote command-line access is required, enable SSH (Secure Shell) on Port 22.",
            "Generate an Ed25519 or RSA-4096 SSH key pair and disable password-based root login in `/etc/ssh/sshd_config` (`PermitRootLogin prohibit-password`).",
            "Restart device and re-scan to ensure Port 23 is closed."
        ],
        "configuration_commands": [
            "# For OpenWrt / Linux-based embedded devices:",
            "/etc/init.d/telnet stop",
            "/etc/init.d/telnet disable",
            "# Enforce SSH only",
            "/etc/init.d/dropbear enable && /etc/init.d/dropbear restart"
        ],
        "firewall_rule": "iptables -A INPUT -p tcp --dport 23 -j DROP"
    },
    "IOT-VULN-005": {
        "title": "Patch Hikvision Web Server Command Injection (CVE-2021-36260)",
        "priority": "P0 - Immediate Action",
        "summary": "Upgrade Hikvision IP camera firmware immediately to a patched release and isolate the camera from the Internet.",
        "steps": [
            "Identify camera model and existing firmware version from the device web UI (Configuration > System > System Settings > Basic Information).",
            "Visit the official Hikvision Security Advisory portal (or your regional distributor) and download the latest patched firmware bundle.",
            "Under Configuration > System > Maintenance > Upgrade, upload the official `.dav` firmware binary.",
            "Allow the camera to complete the firmware flash and reboot without interrupting power.",
            "Change the device admin password immediately after update.",
            "Ensure the camera is NEVER exposed directly via port-forwarding on the router."
        ],
        "configuration_commands": [
            "# Verify firmware patch on camera web portal: Firmware build date must be post-September 2021",
            "# Block camera from WAN outbound communication:",
            "iptables -I FORWARD -s 192.168.1.105 -o eth0 -j DROP"
        ],
        "firewall_rule": "Isolate camera to an isolated Camera VLAN with no default route to the Internet."
    },
    "IOT-VULN-007": {
        "title": "Remediate GoAhead Web Server RCE (CVE-2017-17562)",
        "priority": "P0 - Immediate Action",
        "summary": "Apply OEM firmware patch or restrict web management port access strictly to trusted administrative IP addresses.",
        "steps": [
            "Check the manufacturer support page for a firmware upgrade containing GoAhead >= 3.6.5 or a replaced web server daemon.",
            "If an official firmware update is no longer provided (End-of-Life device), disable the web management interface if possible.",
            "Alternatively, place the device behind a reverse proxy (e.g. NGINX with WAF rules) or restrict Port 80 access via router firewall so only your administrative IP can connect.",
            "Consider retiring this legacy IoT device if security updates are abandoned by the vendor."
        ],
        "configuration_commands": [
            "# Example firewall rule on router to limit management to single admin workstation:",
            "iptables -A FORWARD -p tcp --dport 80 -d 192.168.1.142 ! -s 192.168.1.50 -j DROP"
        ],
        "firewall_rule": "Block inbound HTTP access from all untrusted hosts."
    },
    "IOT-VULN-008": {
        "title": "Remediate RomPager Misfortune Cookie Flaw (CVE-2014-9222)",
        "priority": "P0 - Immediate Action",
        "summary": "Update router firmware to RomPager >= 4.34 or flash with modern open-source firmware (OpenWrt).",
        "steps": [
            "Access router administration page and check for vendor firmware updates.",
            "Disable 'Remote Web Management' / 'Remote WAN Administration' so the web portal is only reachable from LAN.",
            "If the vendor no longer supplies updates for this router, install OpenWrt or replace the gateway router with a modern, actively supported model."
        ],
        "configuration_commands": [
            "# Disable remote management in router web interface under Administration > Remote Management"
        ],
        "firewall_rule": "Ensure Port 80/8080 is blocked on the WAN interface."
    },
    "IOT-VULN-002": {
        "title": "Encrypt MQTT Broker Communications with MQTTS (TLS 8883)",
        "priority": "P1 - High Priority",
        "summary": "Migrate MQTT communications from plaintext Port 1883 to TLS encrypted Port 8883 with username/password or client certificates.",
        "steps": [
            "Generate a Certificate Authority (CA) and server SSL certificates for your MQTT broker.",
            "Configure the broker (e.g., Eclipse Mosquitto) to listen on TLS Port 8883 and require TLS v1.3 / v1.2.",
            "Enable user authentication (`allow_anonymous false` and `password_file /etc/mosquitto/passwd`).",
            "Update IoT client nodes (sensors, thermostats, bridges) with the CA root certificate and switch their target port to 8883.",
            "Disable or block plaintext Port 1883 once all clients have migrated."
        ],
        "configuration_commands": [
            "# In /etc/mosquitto/mosquitto.conf:",
            "listener 8883",
            "cafile /etc/mosquitto/certs/ca.crt",
            "certfile /etc/mosquitto/certs/server.crt",
            "keyfile /etc/mosquitto/certs/server.key",
            "require_certificate false",
            "allow_anonymous false"
        ],
        "firewall_rule": "iptables -A INPUT -p tcp --dport 1883 -j DROP"
    },
    "IOT-VULN-003": {
        "title": "Secure RTSP Video Feed & Enforce Authentication",
        "priority": "P1 - High Priority",
        "summary": "Enable Digest Authentication for RTSP streams and block unauthorized cross-network streaming.",
        "steps": [
            "Log into the camera web dashboard and open Security > Authentication.",
            "Change RTSP Authentication mode from 'None' or 'Basic' to 'Digest'.",
            "Set a strong, unique streaming password (minimum 14 characters) specifically for RTSP clients (e.g. NVR or Home Assistant).",
            "Segment the camera into an isolated CCTV VLAN that cannot be routed to other client workstations."
        ],
        "configuration_commands": [
            "# In camera RTSP settings: enforce digest auth",
            "# Example rtsp URI with authentication: rtsp://secure_user:StrongPassword@192.168.1.105:554/Streaming/Channels/101"
        ],
        "firewall_rule": "iptables -A FORWARD -p tcp --dport 554 -d 192.168.1.105 ! -s 192.168.1.10 -j DROP"
    },
    "IOT-VULN-004": {
        "title": "Disable UPnP / SSDP on Gateway Router & IoT Devices",
        "priority": "P1 - High Priority",
        "summary": "Turn off Universal Plug and Play (UPnP) to prevent unauthorized automated firewall port punch-through and CallStranger abuse.",
        "steps": [
            "Log into your router administration portal (typically at 192.168.1.1).",
            "Navigate to Advanced > Forwarding > UPnP (or NAT / Network > UPnP).",
            "Uncheck 'Enable UPnP' and click Save / Apply.",
            "Verify all current active port mappings and delete any unexpected forwarded ports.",
            "On local Linux/IoT devices, stop and disable `miniupnpd` or `upnpd` services."
        ],
        "configuration_commands": [
            "# On Linux gateway / router:",
            "systemctl stop miniupnpd && systemctl disable miniupnpd",
            "# Drop incoming SSDP multicast requests:",
            "iptables -A INPUT -p udp --dport 1900 -j DROP"
        ],
        "firewall_rule": "iptables -A INPUT -p udp --dport 1900 -j DROP"
    },
    "IOT-VULN-009": {
        "title": "Harden Modbus TCP / Industrial IoT Protocol",
        "priority": "P1 - High Priority",
        "summary": "Isolate industrial control systems behind an encrypted VPN / industrial gateway with deep packet inspection.",
        "steps": [
            "Modbus TCP does not support native encryption or user credentials. NEVER expose Port 502 to untrusted networks or the Internet.",
            "Create a physically or logically isolated OT/ICS VLAN for all PLCs and industrial controllers.",
            "Place an industrial firewall or VPN gateway (such as WireGuard or IPsec) between the corporate/home network and the Modbus devices.",
            "Implement Modbus deep packet inspection (DPI) to restrict Modbus function codes (e.g. block Write Single Coil 0x05 or Write Multiple Registers 0x10 from unauthorized sources)."
        ],
        "configuration_commands": [
            "# Firewall rule: Only allow the authorized SCADA Master IP (e.g. 192.168.1.10) to reach Port 502:",
            "iptables -A FORWARD -p tcp --dport 502 -s 192.168.1.10 -d 192.168.1.200 -j ACCEPT",
            "iptables -A FORWARD -p tcp --dport 502 -d 192.168.1.200 -j DROP"
        ],
        "firewall_rule": "Strict IP whitelisting for all Modbus TCP communications."
    },
    "IOT-VULN-010": {
        "title": "Change Default Credentials & Enforce Strong Password Policy",
        "priority": "P1 - High Priority",
        "summary": "Replace default factory usernames/passwords with high-entropy unique credentials.",
        "steps": [
            "Log into the device configuration portal using initial credentials.",
            "Navigate to User Management / Security > Change Password.",
            "Create a new password that is at least 16 characters long, combining uppercase, lowercase, numbers, and symbols.",
            "If possible, rename or disable the default 'admin' account and create a named administrator.",
            "Store generated credentials in an encrypted password manager (Bitwarden, 1Password, or KeePass)."
        ],
        "configuration_commands": [
            "# On Linux-based IoT device shell:",
            "passwd root",
            "# Remove default weak accounts:",
            "userdel guest 2>/dev/null || true"
        ],
        "firewall_rule": "Fail2Ban or rate-limiting on login interfaces to block brute-force attempts."
    },
    "IOT-VULN-006": {
        "title": "Enforce HTTPS Encryption for Web Management",
        "priority": "P2 - Medium Priority",
        "summary": "Enable TLS/SSL encryption for the web portal and redirect all HTTP traffic to HTTPS.",
        "steps": [
            "Open the device web interface and go to Network > HTTPS / SSL Settings.",
            "Enable HTTPS (Port 443 or 8443).",
            "Generate and install a valid SSL certificate (or a self-signed certificate, or install a private CA certificate).",
            "Enable the 'Force HTTPS Redirection' setting so Port 80 automatically redirects to Port 443.",
            "Ensure administrative sessions use the HTTP 'Secure' and 'SameSite' cookie attributes."
        ],
        "configuration_commands": [
            "# NGINX reverse proxy HTTPS snippet for legacy IoT web interfaces:",
            "server {",
            "    listen 443 ssl http2;",
            "    ssl_certificate /etc/ssl/iot_cert.crt;",
            "    ssl_certificate_key /etc/ssl/iot_key.key;",
            "    location / { proxy_pass http://192.168.1.142:80; }",
            "}"
        ],
        "firewall_rule": "Redirect port 80 to 443 or restrict port 80 access."
    },
    "IOT-VULN-011": {
        "title": "Secure Smart TV / Media Player API Endpoint",
        "priority": "P2 - Medium Priority",
        "summary": "Configure pairing PIN authentication or disable remote control API services on Smart TVs.",
        "steps": [
            "Open Smart TV settings menu > Network / General > Expert Settings.",
            "Turn off 'Power On with Mobile' or 'Device Discovery over LAN' if not required.",
            "Enable 'Access Notification / PIN Prompt' so any new device attempting to send remote control API requests requires entering a PIN displayed on the TV screen.",
            "Place entertainment devices on a separate IoT/Guest Wi-Fi network."
        ],
        "configuration_commands": [
            "# Isolate media player to guest Wi-Fi subnet with client-to-client isolation active."
        ],
        "firewall_rule": "Isolate Smart TVs to separate VLAN with inter-VLAN routing blocked."
    },
    "IOT-VULN-012": {
        "title": "Disable Legacy FTP Service",
        "priority": "P2 - Medium Priority",
        "summary": "Shut down unencrypted FTP daemon and transition to SFTP or SCP.",
        "steps": [
            "In device administration, go to Services > FTP Server.",
            "Disable the FTP service daemon.",
            "If file transfers to/from the IoT device are necessary, configure SFTP (Secure FTP over SSH Port 22) which encrypts both authentication and file payloads."
        ],
        "configuration_commands": [
            "# Disable vsftpd / proftpd:",
            "systemctl stop vsftpd && systemctl disable vsftpd"
        ],
        "firewall_rule": "iptables -A INPUT -p tcp --dport 21 -j DROP"
    }
}

class MitigationGenerator:
    def __init__(self):
        self.plans = MITIGATION_PLANS

    def get_mitigation_for_vuln(self, vuln_id: str) -> Dict[str, Any]:
        """Returns structured mitigation steps for a vulnerability ID."""
        return self.plans.get(vuln_id, {
            "title": f"Remediate Security Issue ({vuln_id})",
            "priority": "P2 - Medium Priority",
            "summary": "Review device settings, close unnecessary open ports, and apply vendor updates.",
            "steps": [
                "Inspect open ports on the device and disable unused services.",
                "Verify the device is running the latest manufacturer firmware.",
                "Isolate the device in a dedicated IoT VLAN."
            ],
            "configuration_commands": [],
            "firewall_rule": "Restrict network access to this port."
        })

    def generate_overall_recommendations(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Produces top-level strategic network hardening recommendations
        based on overall discovered device posture.
        """
        recs = [
            {
                "title": "Implement IoT Network Segmentation (VLANs)",
                "badge": "Architecture Best Practice",
                "importance": "High",
                "description": "Never place IoT devices (cameras, smart plugs, thermostats) on the same subnet as your primary PCs, laptops, and NAS storage. Configure an isolated IoT VLAN (e.g. VLAN 20) with firewall rules preventing IoT devices from initiating connections into your private LAN."
            },
            {
                "title": "Disable UPnP on All Gateways",
                "badge": "Router Hardening",
                "importance": "High",
                "description": "Universal Plug and Play allows internal IoT devices to puncture holes in your router firewall without user notification. Disable UPnP globally in your main router administration portal."
            },
            {
                "title": "Establish an IoT Firmware Maintenance Schedule",
                "badge": "Patch Management",
                "importance": "Medium",
                "description": "Schedule a monthly review of connected IoT devices. Ensure automatic firmware updates are turned on where supported, or verify vendor advisory portals for newly disclosed zero-days."
            },
            {
                "title": "Enforce WPA3 / Strong Wi-Fi Passphrases for IoT SSIDs",
                "badge": "Wireless Security",
                "importance": "Medium",
                "description": "Dedicate a separate 2.4 GHz SSID exclusively for smart home gadgets with Client Isolation (station isolation) enabled so compromised IoT devices cannot attack peer devices."
            }
        ]
        return recs
