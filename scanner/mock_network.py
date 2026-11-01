"""
Simulated IoT Network Lab
Provides realistic IoT device environments with authentic vulnerabilities,
allowing demonstration, grading, and testing without requiring real IoT hardware.
"""

from typing import List, Dict, Any

def get_mock_iot_network() -> List[Dict[str, Any]]:
    """Returns a realistic simulated set of IoT devices with diverse vulnerabilities."""
    return [
        {
            "ip": "192.168.1.105",
            "mac": "44:19:B6:8A:2C:99",
            "hostname": "hikvision-cam-livingroom.local",
            "vendor": "Hangzhou Hikvision Digital Technology",
            "device_type": "IP Security Camera / DVR",
            "icon": "bi-camera-video-fill",
            "confidence": "High",
            "open_ports": [80, 554, 3702],
            "port_details": [
                {"port": 80, "service": "HTTP Web Admin", "banner": "Hikvision-Webs/V5.5.80 (Embedded Linux)"},
                {"port": 554, "service": "RTSP Video Stream", "banner": "RTSP/1.0 200 OK (Unauthenticated Stream)"},
                {"port": 3702, "service": "ONVIF Camera Discovery", "banner": "ONVIF WS-Discovery Probe"}
            ],
            "scan_engine": "Simulated IoT Environment"
        },
        {
            "ip": "192.168.1.118",
            "mac": "24:0A:C4:88:99:A1",
            "hostname": "espressif-thermostat.local",
            "vendor": "Espressif Inc (ESP32/ESP8266 IoT Chip)",
            "device_type": "Smart Thermostat / Environmental Sensor",
            "icon": "bi-thermometer-half",
            "confidence": "High",
            "open_ports": [80, 1883],
            "port_details": [
                {"port": 80, "service": "HTTP Web Admin", "banner": "ESP32 AsyncWebServer/1.2.3"},
                {"port": 1883, "service": "MQTT (Unencrypted)", "banner": "Mosquitto MQTT Broker v2.0.11 (Plaintext)"}
            ],
            "scan_engine": "Simulated IoT Environment"
        },
        {
            "ip": "192.168.1.142",
            "mac": "D8:1F:12:44:BC:7E",
            "hostname": "smart-deadbolt-frontdoor.local",
            "vendor": "Tuya Smart Inc",
            "device_type": "Smart Door Lock / Access Controller",
            "icon": "bi-shield-lock-fill",
            "confidence": "High",
            "open_ports": [23, 80],
            "port_details": [
                {"port": 23, "service": "Telnet", "banner": "BusyBox v1.22.1 (Embedded Linux) built-in shell (ash)"},
                {"port": 80, "service": "HTTP Web Admin", "banner": "GoAhead-Webs/3.6.5 (Legacy Web Server)"}
            ],
            "scan_engine": "Simulated IoT Environment"
        },
        {
            "ip": "192.168.1.1",
            "mac": "50:C7:BF:AA:01:92",
            "hostname": "tplink-archer-gateway.home",
            "vendor": "TP-Link Technologies",
            "device_type": "Wi-Fi Router / Network Gateway",
            "icon": "bi-hdd-network-fill",
            "confidence": "High",
            "open_ports": [53, 80, 1900],
            "port_details": [
                {"port": 53, "service": "DNS", "banner": "dnsmasq-2.80"},
                {"port": 80, "service": "HTTP Web Admin", "banner": "TP-Link HTTP Server / RomPager 4.07"},
                {"port": 1900, "service": "UPnP / SSDP", "banner": "miniupnpd/2.1 UPnP/1.0"}
            ],
            "scan_engine": "Simulated IoT Environment"
        },
        {
            "ip": "192.168.1.160",
            "mac": "50:85:69:FE:33:10",
            "hostname": "samsung-smart-tv.local",
            "vendor": "Samsung Electronics",
            "device_type": "Smart TV / Streaming Media Device",
            "icon": "bi-tv-fill",
            "confidence": "High",
            "open_ports": [1900, 5353, 8080],
            "port_details": [
                {"port": 1900, "service": "UPnP / SSDP", "banner": "Samsung Tizen UPnP/1.0"},
                {"port": 5353, "service": "mDNS / Bonjour", "banner": "Apple-mDNS-Responder"},
                {"port": 8080, "service": "HTTP Alt Web Admin", "banner": "Tizen WebSockets Remote Control API"}
            ],
            "scan_engine": "Simulated IoT Environment"
        },
        {
            "ip": "192.168.1.200",
            "mac": "00:1A:2B:66:77:88",
            "hostname": "bms-controller-plc.facility",
            "vendor": "Schneider / Siemens / BACnet Automation",
            "device_type": "Industrial / Building Control (SCADA/ICS)",
            "icon": "bi-cpu-fill",
            "confidence": "High",
            "open_ports": [80, 502],
            "port_details": [
                {"port": 80, "service": "HTTP Web Admin", "banner": "Embedded SCADA Web Dashboard"},
                {"port": 502, "service": "Modbus TCP (Industrial)", "banner": "Modbus TCP Server (Unauthenticated Unit ID 1)"}
            ],
            "scan_engine": "Simulated IoT Environment"
        }
    ]
