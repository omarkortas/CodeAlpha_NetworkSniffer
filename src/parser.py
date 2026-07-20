"""
parser.py — Dissects a raw Scapy packet into a structured dict.
Extracts Ethernet, IP/IPv6, TCP/UDP/ICMP, and higher-level hints (HTTP, DNS).
"""
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, Raw, ARP


# Well-known ports → human-readable protocol names
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB",
}


def _refine_protocol(default, sport, dport):
    """If a well-known port is involved, use its name instead of TCP/UDP."""
    for p in (dport, sport):
        if p in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[p]
    return default


def parse_packet(packet):
    """
    Return a dict with the parsed fields of a packet:
      timestamp, size, src/dst MAC, src/dst IP, protocol,
      src/dst port, flags, payload, extras (DNS query, ICMP type, ...)
    """
    info = {
        "timestamp": float(packet.time),
        "size": len(packet),
        "src_mac": None, "dst_mac": None,
        "src_ip": None, "dst_ip": None,
        "protocol": "OTHER",
        "src_port": None, "dst_port": None,
        "flags": None,
        "ttl": None,
        "payload": None,
        "extras": {},
    }

    # --- Layer 2: Ethernet ---
    if Ether in packet:
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    # --- ARP (no IP layer) ---
    if ARP in packet:
        info["protocol"] = "ARP"
        info["src_ip"] = packet[ARP].psrc
        info["dst_ip"] = packet[ARP].pdst
        info["extras"]["arp_op"] = "request" if packet[ARP].op == 1 else "reply"
        return info

    # --- Layer 3: IP ---
    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
        info["ttl"] = packet[IP].ttl
    elif IPv6 in packet:
        info["src_ip"] = packet[IPv6].src
        info["dst_ip"] = packet[IPv6].dst

    # --- Layer 4: transport ---
    if TCP in packet:
        info["protocol"] = _refine_protocol("TCP",
                                            packet[TCP].sport,
                                            packet[TCP].dport)
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["flags"] = str(packet[TCP].flags)
    elif UDP in packet:
        info["protocol"] = _refine_protocol("UDP",
                                            packet[UDP].sport,
                                            packet[UDP].dport)
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        info["protocol"] = "ICMP"
        info["extras"]["icmp_type"] = int(packet[ICMP].type)

    # --- DNS extras ---
    if DNS in packet and packet[DNS].qd is not None:
        try:
            qname = packet[DNS].qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="replace")
            info["extras"]["dns_query"] = qname.rstrip(".")
        except Exception:
            pass

    # --- Raw payload ---
    if Raw in packet:
        info["payload"] = bytes(packet[Raw].load)

    return info
