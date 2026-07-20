"""
stats.py — Aggregates capture statistics: protocol mix, top talkers, port usage.
"""
from collections import Counter


class Stats:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = Counter()
        self.top_sources = Counter()
        self.top_destinations = Counter()
        self.top_ports = Counter()

    def update(self, info):
        self.total_packets += 1
        self.total_bytes += info["size"]
        self.protocols[info["protocol"]] += 1

        if info["src_ip"]:
            self.top_sources[info["src_ip"]] += 1
        if info["dst_ip"]:
            self.top_destinations[info["dst_ip"]] += 1
        if info["dst_port"]:
            self.top_ports[info["dst_port"]] += 1
