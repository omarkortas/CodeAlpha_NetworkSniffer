#!/usr/bin/env python3
"""
CodeAlpha — Basic Network Sniffer
Captures and analyzes live network traffic using Scapy.

Usage examples:
    sudo python sniffer.py                          # Sniff on default iface
    sudo python sniffer.py -i eth0 -c 50            # 50 packets on eth0
    sudo python sniffer.py -f "tcp port 80"         # HTTP only
    sudo python sniffer.py -o capture.pcap          # Save to pcap
"""
import argparse
import sys

from scapy.all import sniff, wrpcap

from src.parser import parse_packet
from src.stats import Stats
from src.display import print_banner, print_packet, print_summary


def main():
    ap = argparse.ArgumentParser(
        description="CodeAlpha — Basic Network Sniffer (Python + Scapy)"
    )
    ap.add_argument("-i", "--interface", help="Network interface (default: auto)")
    ap.add_argument("-c", "--count", type=int, default=0,
                    help="Number of packets to capture (0 = infinite until Ctrl+C)")
    ap.add_argument("-f", "--filter", default="",
                    help="BPF filter, e.g. 'tcp port 80' or 'udp'")
    ap.add_argument("-o", "--output",
                    help="Save captured packets to a .pcap file (openable in Wireshark)")
    ap.add_argument("--no-payload", action="store_true",
                    help="Do not display packet payloads")
    args = ap.parse_args()

    print_banner()
    print(f"[*] Interface : {args.interface or 'auto'}")
    print(f"[*] BPF filter: {args.filter or 'none'}")
    print(f"[*] Count     : {'infinite' if args.count == 0 else args.count}")
    print(f"[*] Output    : {args.output or 'not saved'}")
    print("[*] Press Ctrl+C to stop\n")

    stats = Stats()
    saved_packets = []
    counter = {"n": 0}

    def handle(pkt):
        counter["n"] += 1
        info = parse_packet(pkt)
        if args.no_payload:
            info["payload"] = None
        stats.update(info)
        print_packet(counter["n"], info)
        if args.output:
            saved_packets.append(pkt)

    try:
        sniff(
            iface=args.interface,
            prn=handle,
            count=args.count,
            filter=args.filter,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    except PermissionError:
        print("\n[!] Permission denied. Run as root (Linux/macOS) "
              "or as Administrator (Windows).")
        sys.exit(1)
    except OSError as e:
        print(f"\n[!] Interface error: {e}")
        sys.exit(1)

    print_summary(stats)

    if args.output and saved_packets:
        wrpcap(args.output, saved_packets)
        print(f"\n[+] Saved {len(saved_packets)} packets to '{args.output}'")


if __name__ == "__main__":
    main()
