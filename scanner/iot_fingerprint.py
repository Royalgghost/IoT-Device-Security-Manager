"""
IoT Device Fingerprinting Module
Identifies device category, manufacturer, model indicators, and confidence score
based on MAC address OUI, open ports, banners, and hostname.
"""

# Common IoT MAC OUI prefixes (first 3 octets in uppercase, separated by colons)
OUI_DATABASE = {
    # Espressif (ESP8266, ESP32 smart bulbs, switches, sensors)
    "24:0A:C4": "Espressif Inc (ESP32/ESP8266 IoT Chip)",
    "30:AE:A4": "Espressif Inc (ESP32/ESP8266 IoT Chip)",
    "84:F3:EB": "Espressif Inc (Smart Bulb/Switch)",
    "EC:FA:BC": "Espressif Inc (Smart Device)",
    "A4:CF:12": "Espressif Inc (Smart Home Module)",
    
    # Raspberry Pi (frequently used as smart hubs / Home Assistant)
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Foundation",

    # Smart Lighting & Hubs
    "00:17:88": "Philips Lighting (Hue Bridge)",
    "EC:B5:FA": "Signify Netherlands (Philips Hue)",
    "D8:1F:12": "Tuya Smart Inc (Smart Plug / Bulb)",
    "50:EC:50": "Tuya Smart Inc",

    # Cameras / DVRs / NVRs
    "44:19:B6": "Hangzhou Hikvision Digital Technology",
    "C0:56:E3": "Hangzhou Hikvision Digital Technology",
    "3C:EF:8C": "Zhejiang Dahua Technology",
    "B4:A3:82": "Zhejiang Dahua Technology",
    "00:0F:7D": "Axis Communications (IP Camera)",
    "00:40:8C": "Axis Communications (IP Camera)",
    "70:EE:50": "Netgear Arlo (Smart Security Camera)",
    "2C:AA:8E": "Wyze Labs Inc (Smart Cam)",

    # Smart Assistants & Speakers
    "F0:D2:F1": "Amazon Technologies (Echo / Alexa)",
    "68:54:5A": "Amazon Technologies (Fire TV / Echo)",
    "FC:65:DE": "Amazon Technologies",
    "D8:EB:97": "Google LLC (Nest / Home Hub)",
    "18:81:0E": "Google LLC (Chromecast / Nest)",
    "74:C6:3B": "Apple Inc (HomePod / Apple TV)",

    # Smart TVs & Media
    "E8:9E:B4": "Roku Inc (Streaming Player / TV)",
    "D0:51:62": "LG Electronics (Smart TV)",
    "50:85:69": "Samsung Electronics (Smart TV)",
    "64:1C:67": "Sony Corporation (Bravia Smart TV)",

    # Routers & Networking
    "50:C7:BF": "TP-Link Corporation",
    "70:4F:57": "TP-Link Technologies",
    "00:1A:2B": "Cisco Systems",
    "E0:D9:E3": "D-Link Corporation",
    "AC:F8:CC": "Huawei Technologies",
    "64:09:80": "Xiaomi Communications"
}

class DeviceFingerprinter:
    def __init__(self):
        self.oui_db = OUI_DATABASE

    def lookup_vendor_by_mac(self, mac: str) -> str:
        """Find vendor from MAC address OUI."""
        if not mac:
            return "Unknown Vendor"
        clean_mac = mac.upper().replace("-", ":")
        prefix = ":".join(clean_mac.split(":")[:3])
        return self.oui_db.get(prefix, "Generic Network Device")

    def fingerprint_device(self, ip: str, mac: str = "", ports: list = None, banners: dict = None, hostname: str = "") -> dict:
        """
        Classifies the IoT device based on ports, service banners, MAC vendor, and hostname.
        """
        ports = ports or []
        banners = banners or {}
        vendor = self.lookup_vendor_by_mac(mac)
        
        banner_text = " ".join(banners.values()).lower()
        host_lower = (hostname or "").lower()

        device_type = "Generic IoT / Network Host"
        icon = "bi-hdd-network"
        confidence = "Low"

        # 1. IP Camera / Video Surveillance
        if 554 in ports or 3702 in ports or "rtsp" in banner_text or "hikvision" in banner_text or "dahua" in banner_text or "axis" in banner_text or "cam" in host_lower:
            device_type = "IP Security Camera / DVR"
            icon = "bi-camera-video-fill"
            confidence = "High" if (554 in ports and 3702 in ports) or "hikvision" in banner_text else "Medium"
            if "hikvision" in banner_text or "Hikvision" in vendor:
                vendor = "Hikvision"
            elif "dahua" in banner_text or "Dahua" in vendor:
                vendor = "Dahua"
            elif "axis" in banner_text or "Axis" in vendor:
                vendor = "Axis Communications"

        # 2. Industrial / Smart Building IoT
        elif 502 in ports or 47808 in ports or "modbus" in banner_text or "bacnet" in banner_text:
            device_type = "Industrial / Building Control (SCADA/ICS)"
            icon = "bi-cpu-fill"
            confidence = "High"
            vendor = "Schneider / Siemens / BACnet Automation"

        # 3. Smart Hub / Gateway / Bridge
        elif (1883 in ports or 8883 in ports) and (80 in ports or 443 in ports or 8080 in ports):
            device_type = "Smart Home Hub / IoT Gateway"
            icon = "bi-router-fill"
            confidence = "High"
            if "hue" in host_lower or "Philips" in vendor:
                device_type = "Philips Hue Smart Lighting Bridge"
                vendor = "Philips Lighting"
            elif "homeassistant" in host_lower or "hassio" in host_lower:
                device_type = "Home Assistant Smart Hub"
                vendor = "Home Assistant"

        # 4. Smart Thermostat / Sensor
        elif 1883 in ports and (80 not in ports and 443 not in ports):
            device_type = "Smart Thermostat / Environmental Sensor"
            icon = "bi-thermometer-half"
            confidence = "Medium"
            if "espressif" in vendor.lower():
                vendor = "Espressif IoT Sensor"

        # 5. Smart Lock / Access Controller
        elif 23 in ports and (80 in ports or 8080 in ports) and ("lock" in host_lower or "access" in host_lower or "door" in host_lower):
            device_type = "Smart Door Lock / Access Controller"
            icon = "bi-shield-lock-fill"
            confidence = "High"

        # 6. Smart TV / Streaming Media Box
        elif (1900 in ports or 5353 in ports) and ("roku" in host_lower or "tv" in host_lower or "bravia" in host_lower or "Roku" in vendor or "LG" in vendor or "Samsung" in vendor or "Apple TV" in vendor):
            device_type = "Smart TV / Streaming Media Device"
            icon = "bi-tv-fill"
            confidence = "High"

        # 7. Network Router / Gateway
        elif 53 in ports and (80 in ports or 443 in ports or 8080 in ports):
            device_type = "Wi-Fi Router / Network Gateway"
            icon = "bi-hdd-network-fill"
            confidence = "High"

        # 8. Embedded Linux / IoT Appliance with Telnet
        elif 23 in ports:
            device_type = "Embedded IoT Appliance (Legacy Telnet Enabled)"
            icon = "bi-terminal-fill"
            confidence = "Medium"

        # 9. Smart Plug / Smart Bulb (Espressif / Tuya)
        elif "espressif" in vendor.lower() or "tuya" in vendor.lower() or "plug" in host_lower or "bulb" in host_lower:
            device_type = "Smart Plug / Connected Lighting"
            icon = "bi-lightbulb-fill"
            confidence = "Medium"

        return {
            "device_type": device_type,
            "vendor": vendor,
            "icon": icon,
            "confidence": confidence,
            "hostname": hostname or f"iot-host-{ip.replace('.', '-')}"
        }
