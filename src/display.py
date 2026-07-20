"""
display.py — Pretty terminal output with cross-platform colors (colorama).
"""
from colorama import Fore, Style, init

init(autoreset=True)

PROTO_COLORS = {
    "TCP":   Fore.CYAN,
    "UDP":   Fore.MAGENTA,
    "ICMP":  Fore.YELLOW,
    "HTTP":  Fore.GREEN,
    "HTTPS": Fore.GREEN,
    "DNS":   Fore.BLUE,
    "ARP":   Fore.LIGHTRED_EX,
    "SSH":   Fore.LIGHTCYAN_EX,
    "FTP":   Fore.LIGHTMAGENTA_EX,
}


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
    ╔═══════════════════════════════════════════════╗
    ║   CodeAlpha — Basic Network Sniffer           ║
    ║   Python 3 · Scapy                            ║
    ╚═══════════════════════════════════════════════╝
    """)


def _fmt_endpoint(ip, port):
    if ip is None:
        return "N/A"
    if port is None:
        return ip
    return f"{ip}:{port}"


def _hex_and_ascii(data, limit=48):
    preview = data[:limit]
    hex_str = " ".join(f"{b:02x}" for b in preview)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
    truncated = " ..." if len(data) > limit else ""
    return hex_str + truncated, ascii_str + truncated


def print_packet(idx, info):
    color = PROTO_COLORS.get(info["protocol"], Fore.WHITE)
    src = _fmt_endpoint(info["src_ip"], info["src_port"])
    dst = _fmt_endpoint(info["dst_ip"], info["dst_port"])

    header = (f"{Fore.WHITE}{Style.BRIGHT}[#{idx:>4}] "
              f"{color}{info['protocol']:<7}{Style.RESET_ALL} "
              f"{src}  →  {dst}  "
              f"{Fore.LIGHTBLACK_EX}({info['size']} B)")
    print("\n" + header)

    if info["ttl"] is not None:
        print(f"   ├─ TTL   : {info['ttl']}")
    if info["flags"]:
        print(f"   ├─ Flags : {info['flags']}")
    if info["extras"].get("dns_query"):
        print(f"   ├─ DNS   : {Fore.BLUE}{info['extras']['dns_query']}")
    if info["extras"].get("arp_op"):
        print(f"   ├─ ARP   : {info['extras']['arp_op']}")
    if info["extras"].get("icmp_type") is not None:
        print(f"   ├─ ICMP  : type {info['extras']['icmp_type']}")

    if info["payload"]:
        hex_s, ascii_s = _hex_and_ascii(info["payload"])
        print(f"   ├─ Hex   : {Fore.LIGHTBLACK_EX}{hex_s}")
        print(f"   └─ ASCII : {Fore.LIGHTBLACK_EX}{ascii_s}")


def print_summary(stats):
    print(Fore.CYAN + Style.BRIGHT + "\n\n═══════════ CAPTURE SUMMARY ═══════════")
    print(f"Total packets : {stats.total_packets}")
    print(f"Total bytes   : {stats.total_bytes:,}")

    print(Fore.YELLOW + "\n▸ Protocol distribution")
    for proto, n in stats.protocols.most_common():
        pct = 100 * n / stats.total_packets if stats.total_packets else 0
        print(f"    {proto:<10} {n:>6}  ({pct:5.1f}%)")

    print(Fore.YELLOW + "\n▸ Top 5 source IPs")
    for ip, n in stats.top_sources.most_common(5):
        print(f"    {ip:<40} {n}")

    print(Fore.YELLOW + "\n▸ Top 5 destination IPs")
    for ip, n in stats.top_destinations.most_common(5):
        print(f"    {ip:<40} {n}")

    print(Fore.YELLOW + "\n▸ Top 5 destination ports")
    for port, n in stats.top_ports.most_common(5):
        print(f"    {port:<6} {n}")

    print(Fore.CYAN + Style.BRIGHT + "═══════════════════════════════════════\n")
