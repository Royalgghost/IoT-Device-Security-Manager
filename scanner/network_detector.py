import socket
import ipaddress
import subprocess
import re
import platform

def get_local_ip() -> str:
    """Determine the primary local IPv4 address connected to the network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually transmit packets, just routes to find default interface
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_local_network_info() -> dict:
    """
    Returns detected network information including:
    - local_ip
    - subnet_cidr
    - is_private
    - detected_gateway
    """
    local_ip = get_local_ip()
    is_loopback = local_ip.startswith("127.")
    
    if is_loopback:
        return {
            "local_ip": "127.0.0.1",
            "subnet_cidr": "127.0.0.1/32",
            "subnet_network": "127.0.0.1",
            "is_loopback": True,
            "recommended_targets": ["127.0.0.1", "demo-lab"]
        }

    try:
        ip_obj = ipaddress.IPv4Interface(f"{local_ip}/24")
        network_cidr = str(ip_obj.network)
        first_few_hosts = [str(h) for i, h in enumerate(ip_obj.network.hosts()) if i < 10]
        recommended_gateway = str(list(ip_obj.network.hosts())[0]) if list(ip_obj.network.hosts()) else ""
    except Exception:
        network_cidr = f"{local_ip}/32"
        recommended_gateway = ""

    return {
        "local_ip": local_ip,
        "subnet_cidr": network_cidr,
        "recommended_gateway": recommended_gateway,
        "is_loopback": False,
        "recommended_targets": [network_cidr, local_ip, "demo-lab"]
    }

def get_arp_table() -> dict:
    """
    Extracts MAC addresses from the system ARP table to assist device fingerprinting.
    Returns a dict mapping IP -> MAC.
    """
    arp_map = {}
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                # Matches IP and physical address like: 192.168.1.1  00-11-22-33-44-55
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", line)
                if match:
                    ip, mac = match.groups()
                    arp_map[ip] = mac.replace('-', ':').upper()
        else:
            output = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*lladdr\s+([0-9a-fA-F:]{17})", line)
                if match:
                    ip, mac = match.groups()
                    arp_map[ip] = mac.upper()
    except Exception:
        pass
    return arp_map
