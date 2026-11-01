import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'iot-sec-manager-secret-key-2026')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

    # Common IoT ports to scan
    # 21: FTP (Legacy firmware / cleartext file transfer)
    # 22: SSH (Remote management)
    # 23: Telnet (Legacy cleartext IoT remote shell - high risk)
    # 53: DNS (Router / Gateway)
    # 80: HTTP (Web Admin UI)
    # 443: HTTPS (Encrypted Web Admin UI)
    # 554: RTSP (Real Time Streaming Protocol - IP Cameras)
    # 1883: MQTT (Cleartext IoT Message Broker)
    # 1900: UPnP / SSDP (Discovery protocol - CallStranger vulnerability)
    # 3702: ONVIF / WS-Discovery (IP Security Cameras)
    # 5000: UPnP / Synology / HTTP Management
    # 5001: Synology / HTTPS Management
    # 5353: mDNS / Bonjour (ZeroConf Device Discovery)
    # 8080: HTTP-Alt (Web management)
    # 8443: HTTPS-Alt (Secure Web management)
    # 8883: MQTTS (Secure MQTT over TLS)
    # 502: Modbus TCP (Industrial IoT / SCADA)
    # 47808: BACnet (Building Automation)
    IOT_PORTS = [
        21, 22, 23, 53, 80, 443, 502, 554, 1883,
        1900, 3702, 5000, 5001, 5353, 8080, 8443, 8883, 47808
    ]

    PORT_SERVICE_MAP = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        53: "DNS",
        80: "HTTP Web Admin",
        443: "HTTPS Web Admin",
        502: "Modbus TCP (Industrial)",
        554: "RTSP Video Stream",
        1883: "MQTT (Unencrypted)",
        1900: "UPnP / SSDP",
        3702: "ONVIF Camera Discovery",
        5000: "UPnP / Web Service",
        5001: "Secure Web Service",
        5353: "mDNS / Bonjour",
        8080: "HTTP Alt Web Admin",
        8443: "HTTPS Alt Web Admin",
        8883: "MQTT over TLS (Secure)",
        47808: "BACnet Building Automation"
    }

    # Standard Nmap paths on Windows
    NMAP_SEARCH_PATHS = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Nmap\nmap.exe"
    ]

    # Socket scan settings
    SOCKET_TIMEOUT = 1.0  # seconds
    MAX_WORKERS = 40      # concurrent threads
