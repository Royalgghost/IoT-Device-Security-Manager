import socket
import ipaddress
import concurrent.futures
from typing import Callable, List, Dict, Any
from config import Config
from .network_detector import get_arp_table
from .iot_fingerprint import DeviceFingerprinter

class SocketScanner:
    def __init__(self, ports: List[int] = None, timeout: float = None, max_workers: int = None):
        self.ports = ports or Config.IOT_PORTS
        self.timeout = timeout or Config.SOCKET_TIMEOUT
        self.max_workers = max_workers or Config.MAX_WORKERS
        self.fingerprinter = DeviceFingerprinter()

    def grab_banner(self, ip: str, port: int) -> str:
        """Attempts to retrieve service banner for identified open port."""
        banner = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((ip, port))
            if port in [80, 8080, 5000]:
                request = b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: IoT-Sec-Scanner\r\nConnection: close\r\n\r\n"
                s.sendall(request)
                response = s.recv(1024).decode('utf-8', errors='ignore')
                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.strip()
                        break
                if not banner and response:
                    banner = response.splitlines()[0] if response.splitlines() else "HTTP Web Service"
            elif port == 554:
                # RTSP probe
                req = b"OPTIONS rtsp://" + ip.encode() + b"/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IoT-Sec-Scanner\r\n\r\n"
                s.sendall(req)
                res = s.recv(512).decode('utf-8', errors='ignore')
                if "RTSP" in res:
                    banner = "RTSP Streaming Media Server"
            elif port in [21, 22, 23]:
                # Service banner line
                res = s.recv(512).decode('utf-8', errors='ignore').strip()
                if res:
                    banner = res.splitlines()[0][:80]
            elif port == 1883:
                banner = "MQTT Broker (Cleartext Port 1883)"
            elif port == 8883:
                banner = "MQTTS Secure Broker (TLS Port 8883)"
        except Exception:
            pass
        finally:
            s.close()
        return banner or Config.PORT_SERVICE_MAP.get(port, f"Service/{port}")

    def scan_host_port(self, ip: str, port: int) -> Dict[str, Any]:
        """Test a single host port."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = self.grab_banner(ip, port)
                return {"port": port, "open": True, "service": Config.PORT_SERVICE_MAP.get(port, "Unknown"), "banner": banner}
        except Exception:
            pass
        finally:
            s.close()
        return {"port": port, "open": False}

    def scan_single_host(self, ip: str, mac_table: dict = None) -> Dict[str, Any]:
        """Scans all designated IoT ports on a specific IP."""
        mac_table = mac_table or {}
        open_ports = []
        banners = {}

        for port in self.ports:
            res = self.scan_host_port(ip, port)
            if res.get("open"):
                open_ports.append(port)
                banners[port] = res.get("banner", "")

        if not open_ports:
            return None

        # Resolve hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = f"device-{ip.replace('.', '-')}"

        mac = mac_table.get(ip, "")
        fp = self.fingerprinter.fingerprint_device(
            ip=ip,
            mac=mac,
            ports=open_ports,
            banners=banners,
            hostname=hostname
        )

        port_details = []
        for p in open_ports:
            port_details.append({
                "port": p,
                "service": Config.PORT_SERVICE_MAP.get(p, "Unknown"),
                "banner": banners.get(p, "")
            })

        return {
            "ip": ip,
            "mac": mac or "Unknown",
            "hostname": fp["hostname"],
            "vendor": fp["vendor"],
            "device_type": fp["device_type"],
            "icon": fp["icon"],
            "confidence": fp["confidence"],
            "open_ports": open_ports,
            "port_details": port_details,
            "scan_engine": "Native Python Socket Engine"
        }

    def scan_network(self, target: str, progress_callback: Callable[[int, int, str], None] = None) -> List[Dict[str, Any]]:
        """
        Scans a target IP, CIDR subnet, or list of IPs.
        Invokes progress_callback(current_step, total_steps, message).
        """
        mac_table = get_arp_table()
        
        # Parse targets
        targets = []
        try:
            if "/" in target:
                net = ipaddress.ip_network(target, strict=False)
                # Limit subnet scan to /24 (254 hosts) for responsiveness
                hosts = list(net.hosts())
                if len(hosts) > 254:
                    hosts = hosts[:254]
                targets = [str(h) for h in hosts]
            elif "-" in target:
                # e.g. 192.168.1.1-192.168.1.50
                start_ip, end_ip = target.split("-")
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                curr = start
                while curr <= end:
                    targets.append(str(curr))
                    curr += 1
            else:
                targets = [target.strip()]
        except Exception as e:
            targets = [target]

        total_targets = len(targets)
        discovered_devices = []

        if progress_callback:
            progress_callback(5, 100, f"Scanning {total_targets} host(s) for active IoT ports...")

        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_single_host, ip, mac_table): ip for ip in targets}
            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                ip = future_to_ip[future]
                try:
                    dev = future.result()
                    if dev:
                        discovered_devices.append(dev)
                        if progress_callback:
                            pct = 5 + int((completed / total_targets) * 85)
                            progress_callback(pct, 100, f"Discovered open IoT device at {ip} ({dev['device_type']})")
                    else:
                        if progress_callback and completed % 10 == 0:
                            pct = 5 + int((completed / total_targets) * 85)
                            progress_callback(pct, 100, f"Checked {completed}/{total_targets} hosts...")
                except Exception:
                    pass

        if progress_callback:
            progress_callback(95, 100, f"Completed port probing. Found {len(discovered_devices)} host(s).")

        return discovered_devices
