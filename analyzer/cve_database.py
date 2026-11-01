"""
Curated IoT Vulnerability and CVE Knowledge Base
Contains standardized vulnerability definitions, severity classifications,
CVSS v3.1 scores, attack vectors, and associated threat impacts.
"""

CVE_DEFINITIONS = [
    {
        "id": "IOT-VULN-001",
        "title": "Cleartext Telnet Service Enabled (Mirai Target)",
        "cve": "CWE-319 / CWE-287",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Insecure Remote Management",
        "description": "Port 23 (Telnet) is listening. Telnet transmits all communication, including administrative credentials and commands, in plaintext without encryption. This is the primary infection vector for IoT botnets like Mirai, Mozi, and Gafgyt.",
        "impact": "Remote unauthenticated attackers can sniff credentials, brute-force weak passwords, hijack the terminal, and recruit the device into a botnet DDoS cluster.",
        "trigger": lambda ports, banners, dev_type: 23 in ports
    },
    {
        "id": "IOT-VULN-005",
        "title": "Hikvision Web Server Remote Code Execution",
        "cve": "CVE-2021-36260",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Firmware Vulnerability",
        "description": "A command injection vulnerability exists in the web server of multiple Hikvision IP cameras. Due to insufficient input validation in message handling, an attacker can send specially crafted messages to execute arbitrary root commands.",
        "impact": "Full root takeover of the IP camera, unauthorized video interception, and potential pivot point for lateral network movement.",
        "trigger": lambda ports, banners, dev_type: (80 in ports or 443 in ports or 554 in ports) and ("hikvision" in str(banners).lower() or dev_type == "IP Security Camera / DVR" and "hikvision" in dev_type.lower())
    },
    {
        "id": "IOT-VULN-007",
        "title": "GoAhead Embedded Web Server Remote Code Execution",
        "cve": "CVE-2017-17562",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Web Management Flaw",
        "description": "GoAhead Web Server versions prior to 3.6.5 initialize the environment using untrusted HTTP request parameters, permitting remote code execution via CGI scripts.",
        "impact": "Remote unauthenticated attackers can execute arbitrary code on the IoT operating system with web server privileges.",
        "trigger": lambda ports, banners, dev_type: any("goahead" in str(b).lower() for b in banners.values())
    },
    {
        "id": "IOT-VULN-008",
        "title": "RomPager 'Misfortune Cookie' Memory Corruption",
        "cve": "CVE-2014-9222",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Router Gateway Flaw",
        "description": "Allegro RomPager embedded web server before version 4.34 contains an out-of-bounds pointer write vulnerability triggered by crafted HTTP cookie headers.",
        "impact": "Allows attackers to corrupt device memory, overwrite DNS server settings, disable firewall rules, or gain administrative access to the router.",
        "trigger": lambda ports, banners, dev_type: any("rompager" in str(b).lower() for b in banners.values())
    },
    {
        "id": "IOT-VULN-002",
        "title": "Unencrypted MQTT Telemetry & Control Broker",
        "cve": "CWE-319",
        "severity": "HIGH",
        "cvss": 7.5,
        "category": "Insecure IoT Protocol",
        "description": "Port 1883 (MQTT) is active without TLS encryption. Telemetry, sensor readings, and IoT actuation command payloads are transmitted over the local network in cleartext.",
        "impact": "Local eavesdropping, message spoofing, injection of malicious control commands (e.g. tampering with thermostat temperature, unlocking actuators).",
        "trigger": lambda ports, banners, dev_type: 1883 in ports and 8883 not in ports
    },
    {
        "id": "IOT-VULN-003",
        "title": "Exposed RTSP Video Streaming Service",
        "cve": "CWE-306",
        "severity": "HIGH",
        "cvss": 7.5,
        "category": "Surveillance Privacy Risk",
        "description": "Port 554 (RTSP) is exposed and listening. Many embedded camera models fail to enforce mandatory digest authentication on live streaming endpoints (e.g. /live/ch0, /h264Preview_01_main).",
        "impact": "Unauthorized streaming and recording of private video feeds, physical security surveillance breach.",
        "trigger": lambda ports, banners, dev_type: 554 in ports
    },
    {
        "id": "IOT-VULN-004",
        "title": "UPnP / SSDP Exposed (CallStranger & NAT Injection)",
        "cve": "CVE-2020-12695",
        "severity": "HIGH",
        "cvss": 7.5,
        "category": "Network Exposure",
        "description": "Port 1900 (SSDP/UPnP) is open. UPnP allows automatic, unauthenticated port forwarding on routers and is vulnerable to the CallStranger vulnerability which can be abused for DDoS amplification and internal port scanning.",
        "impact": "Malicious internal devices can puncture holes in the router firewall to expose internal IoT devices to the public Internet without user consent.",
        "trigger": lambda ports, banners, dev_type: 1900 in ports
    },
    {
        "id": "IOT-VULN-009",
        "title": "Unauthenticated Industrial Modbus TCP Protocol Exposed",
        "cve": "CWE-306 / SCADA-RISK",
        "severity": "HIGH",
        "cvss": 8.6,
        "category": "Industrial IoT / SCADA Exposure",
        "description": "Port 502 (Modbus TCP) is listening. Modbus has zero native authentication or integrity checks; any client that can reach the port can read coil states and write register setpoints.",
        "impact": "Direct physical tampering with industrial actuators, HVAC units, power relays, or building environmental controls.",
        "trigger": lambda ports, banners, dev_type: 502 in ports
    },
    {
        "id": "IOT-VULN-010",
        "title": "Default or Weak Factory Credentials Risk",
        "cve": "CWE-798 / CWE-521",
        "severity": "HIGH",
        "cvss": 8.1,
        "category": "Authentication Weakness",
        "description": "Embedded device detected with administrative management ports open (Telnet, HTTP, or FTP) without active rate-limiting or multifactor protection. Over 70% of IoT devices retain factory default passwords (e.g., admin:admin, root:123456).",
        "impact": "Instant device compromise via dictionary brute-force.",
        "trigger": lambda ports, banners, dev_type: (23 in ports or (80 in ports and "GoAhead" in str(banners))) and dev_type != "Generic Network Device"
    },
    {
        "id": "IOT-VULN-006",
        "title": "Insecure HTTP Web Management Interface (No HTTPS)",
        "cve": "CWE-319",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "category": "Insecure Management Protocol",
        "description": "Device management interface is served over unencrypted HTTP (Port 80/8080) without automatic redirection to HTTPS (Port 443/8443).",
        "impact": "Session cookies and administrator credentials can be intercepted by an attacker sharing the same local Wi-Fi or Ethernet segment.",
        "trigger": lambda ports, banners, dev_type: (80 in ports or 8080 in ports) and (443 not in ports and 8443 not in ports)
    },
    {
        "id": "IOT-VULN-011",
        "title": "Unauthenticated Smart TV / IoT REST API",
        "cve": "CWE-285",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "category": "API Security",
        "description": "Port 8080 is exposing an unauthenticated device control API or WebSocket service commonly found on Smart TVs and media bridges.",
        "impact": "Attackers on the LAN can send remote commands, launch arbitrary media, alter volume, or retrieve stored device information.",
        "trigger": lambda ports, banners, dev_type: 8080 in ports and dev_type == "Smart TV / Streaming Media Device"
    },
    {
        "id": "IOT-VULN-012",
        "title": "Legacy Cleartext FTP Protocol Detected",
        "cve": "CWE-319",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "category": "Legacy File Transfer",
        "description": "Port 21 (FTP) is listening. FTP transmits file contents and authentication credentials in plaintext.",
        "impact": "Interception of firmware backup files, configurations, or credentials traversing the local network segment.",
        "trigger": lambda ports, banners, dev_type: 21 in ports
    }
]
