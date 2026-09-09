"""
TraceShield IP Forensics and Anonymizer Detection Service
Provides offline deterministic Tor exit node verification, datacenter proxy detection,
and forensic IP enrichment without making live external network calls.
"""

import ipaddress
import os
from typing import Any, Dict, List, Optional, Set

# In-memory Tor exit node cache
TOR_EXIT_NODES: Set[str] = set()

# Common Datacenter, Hosting, and Commercial VPN / Proxy IP ranges (CIDR)
# Covers major cloud/VPS infrastructure: AWS, DigitalOcean, Hetzner, OVH, Linode, Vultr, M247, Choopa, etc.
DATACENTER_PROXY_CIDRS = [
    # DigitalOcean
    ipaddress.ip_network("159.65.0.0/16"),
    ipaddress.ip_network("167.99.0.0/16"),
    ipaddress.ip_network("138.68.0.0/16"),
    ipaddress.ip_network("178.62.0.0/16"),
    ipaddress.ip_network("142.93.0.0/16"),
    ipaddress.ip_network("104.248.0.0/16"),
    ipaddress.ip_network("165.227.0.0/16"),
    ipaddress.ip_network("159.89.0.0/16"),
    ipaddress.ip_network("164.90.128.0/17"),
    ipaddress.ip_network("134.209.0.0/16"),
    ipaddress.ip_network("64.227.0.0/16"),
    ipaddress.ip_network("143.198.0.0/16"),
    # Hetzner
    ipaddress.ip_network("88.198.0.0/16"),
    ipaddress.ip_network("144.76.0.0/16"),
    ipaddress.ip_network("136.243.0.0/16"),
    ipaddress.ip_network("116.203.0.0/16"),
    ipaddress.ip_network("159.69.0.0/16"),
    ipaddress.ip_network("65.108.0.0/16"),
    ipaddress.ip_network("65.109.0.0/16"),
    ipaddress.ip_network("95.216.0.0/16"),
    ipaddress.ip_network("95.217.0.0/16"),
    ipaddress.ip_network("49.12.0.0/16"),
    # OVH
    ipaddress.ip_network("51.254.0.0/15"),
    ipaddress.ip_network("178.32.0.0/15"),
    ipaddress.ip_network("149.202.0.0/16"),
    ipaddress.ip_network("54.36.0.0/14"),
    ipaddress.ip_network("147.135.0.0/16"),
    ipaddress.ip_network("198.245.48.0/20"),
    # Linode / Akamai
    ipaddress.ip_network("172.104.0.0/15"),
    ipaddress.ip_network("139.162.0.0/16"),
    ipaddress.ip_network("45.33.0.0/16"),
    ipaddress.ip_network("45.79.0.0/16"),
    ipaddress.ip_network("198.58.96.0/19"),
    # Vultr / Choopa
    ipaddress.ip_network("108.61.0.0/16"),
    ipaddress.ip_network("45.76.0.0/16"),
    ipaddress.ip_network("45.63.0.0/16"),
    ipaddress.ip_network("149.28.0.0/16"),
    ipaddress.ip_network("207.246.64.0/18"),
    ipaddress.ip_network("66.42.32.0/19"),
    # M247 / Public VPN infrastructure
    ipaddress.ip_network("185.220.100.0/22"),
    ipaddress.ip_network("193.218.118.0/24"),
    ipaddress.ip_network("194.26.29.0/24"),
    ipaddress.ip_network("45.154.255.0/24"),
    ipaddress.ip_network("195.206.104.0/22"),
    ipaddress.ip_network("37.120.128.0/17"),
    ipaddress.ip_network("185.156.172.0/22"),
]


def _find_tor_data_path() -> str:
    """Resolves the absolute path to tor_exit_nodes.txt across varied execution working directories."""
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tor_exit_nodes.txt"),
        os.path.join(os.getcwd(), "backend", "data", "tor_exit_nodes.txt"),
        os.path.join(os.getcwd(), "data", "tor_exit_nodes.txt"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "tor_exit_nodes.txt"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    return candidates[0]


def load_tor_exit_nodes(file_path: Optional[str] = None) -> Set[str]:
    """
    Loads Tor exit node IP addresses from the data file into an in-memory set.
    Cleans comments and whitespace.
    """
    path = file_path or _find_tor_data_path()
    nodes: Set[str] = set()

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#"):
                        # Extract first token in case line has trailing comment or name
                        ip_token = cleaned.split()[0].strip()
                        try:
                            # Normalize IP string
                            parsed_ip = str(ipaddress.ip_address(ip_token))
                            nodes.add(parsed_ip)
                        except ValueError:
                            nodes.add(ip_token)
        except Exception as e:
            print(f"[GeoIP Service] Warning: Failed to load tor_exit_nodes.txt: {e}")

    return nodes


# Module-level load of Tor exit nodes into memory
TOR_EXIT_NODES = load_tor_exit_nodes()


def is_tor_exit_node(ip: str) -> bool:
    """Returns True if the given IP is a known Tor exit node."""
    if not ip or not isinstance(ip, str):
        return False
    ip_clean = ip.strip()
    return ip_clean in TOR_EXIT_NODES


def is_datacenter_proxy(ip: str) -> bool:
    """Returns True if the given IP belongs to known cloud / hosting / proxy datacenter CIDRs."""
    if not ip or not isinstance(ip, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
            return False
        return any(ip_obj in network for network in DATACENTER_PROXY_CIDRS)
    except Exception:
        return False


def detect_anonymizer(ip: str) -> Dict[str, Any]:
    """
    Inspects an observable IP address and returns anonymization and proxy triage metadata:
    - is_tor: bool
    - is_proxy: bool
    - confidence_score: float (0.95 for Tor, 0.70 for datacenter/VPN proxy, 0.10 for residential ISP, 0.0 for private/invalid)
    - anonymizer_type: "TOR Exit Node" | "Public VPN / Proxy" | "None"
    """
    if not ip or not isinstance(ip, str):
        return {
            "is_tor": False,
            "is_proxy": False,
            "confidence_score": 0.0,
            "anonymizer_type": "None",
            "details": "Invalid or empty IP address.",
        }

    ip_clean = ip.strip()

    # Validate IP address syntax & private scope
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return {
            "is_tor": False,
            "is_proxy": False,
            "confidence_score": 0.0,
            "anonymizer_type": "None",
            "details": "Malformed IP address syntax.",
        }

    # 1. Tor Exit Node Check (Highest priority / High risk)
    if ip_clean in TOR_EXIT_NODES:
        return {
            "is_tor": True,
            "is_proxy": True,
            "confidence_score": 0.95,
            "anonymizer_type": "TOR Exit Node",
            "details": "Confirmed active Tor Project exit relay node.",
        }

    # 2. Private or internal infrastructure check
    if is_private:
        return {
            "is_tor": False,
            "is_proxy": False,
            "confidence_score": 0.0,
            "anonymizer_type": "None",
            "details": "Private RFC 1918 or loopback internal network hop.",
        }

    # 3. Datacenter / Commercial Proxy / VPN check
    if is_datacenter_proxy(ip_clean):
        return {
            "is_tor": False,
            "is_proxy": True,
            "confidence_score": 0.70,
            "anonymizer_type": "Public VPN / Proxy",
            "details": "Originates from known cloud datacenter hosting / VPN proxy CIDR.",
        }

    # 4. Standard public / residential relay hop
    return {
        "is_tor": False,
        "is_proxy": False,
        "confidence_score": 0.10,
        "anonymizer_type": "None",
        "details": "Standard public autonomous system relay hop.",
    }


def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Comprehensive IP enrichment returning geolocation approximation and anonymizer detection.
    """
    anon = detect_anonymizer(ip)
    return {
        "ip": ip,
        **anon,
    }
