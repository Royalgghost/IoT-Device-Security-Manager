import shutil
import os
from typing import List, Dict, Any, Callable, Tuple
from config import Config
from .network_detector import get_arp_table
from .iot_fingerprint import DeviceFingerprinter

def find_nmap_binary() -> str:
    """Finds nmap binary in system PATH or standard Windows directories."""
    path = shutil.which("nmap")
    if path:
        return path
    for p in Config.NMAP_SEARCH_PATHS:
        if os.path.isfile(p):
            return p
    return ""

def is_nmap_available() -> Tuple[bool, str]:
    """Returns True and path if nmap binary is available, otherwise False and reason."""
    path = find_nmap_binary()
    if path:
        return True, path
    return False, "Nmap binary not found in PATH or standard installation directories."

class NmapScanner:
    def __init__(self, ports: List[int] = None):
        self.ports = ports or Config.IOT_PORTS
        self.fingerprinter = DeviceFingerprinter()
        self.nmap_path = find_nmap_binary()
        if self.nmap_path and os.path.dirname(self.nmap_path) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = os.path.dirname(self.nmap_path) + os.pathsep + os.environ.get("PATH", "")

    def scan_network(self, target: str, arguments: str = "-sV -T4 --open", progress_callback: Callable[[int, int, str], None] = None) -> List[Dict[str, Any]]:
        """
        Executes an Nmap scan using python-nmap on the designated target.
        """
        import nmap
        nm = nmap.PortScanner()
        ports_str = ",".join(str(p) for p in self.ports)
        full_args = f"-p {ports_str} {arguments}"

        if progress_callback:
            progress_callback(10, 100, f"Starting Nmap scanner on target {target} with ports {ports_str}...")

        try:
            nm.scan(hosts=target, arguments=full_args)
        except Exception as e:
            if progress_callback:
                progress_callback(50, 100, f"Nmap scan encounter error: {str(e)}")
            raise

        arp_table = get_arp_table()
        discovered_devices = []

        all_hosts = nm.all_hosts()
        total_hosts = len(all_hosts)
        
        if progress_callback:
            progress_callback(60, 100, f"Nmap discovered {total_hosts} responding host(s). Parsing services...")

        for idx, host in enumerate(all_hosts):
            if nm[host].state() != 'up':
                continue

            open_ports = []
            port_details = []
            banners = {}

            for proto in nm[host].all_protocols():
                ports_found = nm[host][proto].keys()
                for p in sorted(ports_found):
                    p_info = nm[host][proto][p]
                    if p_info.get('state') == 'open':
                        open_ports.append(p)
                        svc_name = p_info.get('name', Config.PORT_SERVICE_MAP.get(p, 'Unknown'))
                        product = p_info.get('product', '')
                        version = p_info.get('version', '')
                        banner = f"{product} {version}".strip() or svc_name
                        banners[p] = banner
                        port_details.append({
                            "port": p,
                            "service": svc_name,
                            "banner": banner,
                            "product": product,
                            "version": version
                        })

            if not open_ports:
                continue

            hostname = nm[host].hostname() or f"device-{host.replace('.', '-')}"
            
            # Extract MAC and vendor if present in nmap output or fallback to ARP table
            mac = ""
            vendor = ""
            if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                mac = nm[host]['addresses']['mac'].upper()
            if not mac:
                mac = arp_table.get(host, "")

            if 'vendor' in nm[host] and mac in nm[host]['vendor']:
                vendor = nm[host]['vendor'][mac]

            fp = self.fingerprinter.fingerprint_device(
                ip=host,
                mac=mac,
                ports=open_ports,
                banners=banners,
                hostname=hostname
            )

            discovered_devices.append({
                "ip": host,
                "mac": mac or "Unknown",
                "hostname": hostname,
                "vendor": vendor or fp["vendor"],
                "device_type": fp["device_type"],
                "icon": fp["icon"],
                "confidence": fp["confidence"],
                "open_ports": open_ports,
                "port_details": port_details,
                "scan_engine": "Nmap PortScanner"
            })

            if progress_callback:
                pct = 60 + int(((idx + 1) / max(total_hosts, 1)) * 35)
                progress_callback(pct, 100, f"Analyzed host {host} ({fp['device_type']})")

        return discovered_devices
