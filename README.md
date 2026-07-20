# 🕵️ Basic Network Sniffer

> **Task 1** of Cyber Security Internship.  
> A Python-based network sniffer that captures live traffic, dissects each packet layer by layer, and produces a colored real-time output plus a final capture summary.

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- 📡 **Live packet capture** on any network interface
- 🧬 **Layer-by-layer dissection**: Ethernet → IP/IPv6 → TCP/UDP/ICMP → application
- 🎯 **Protocol detection** for HTTP, HTTPS, DNS, SSH, FTP, DHCP, MySQL, RDP, and more
- 📊 **Real-time statistics**: protocol distribution, top talkers, top ports
- 🔎 **Payload preview** in both hex and ASCII
- 🧠 **BPF filter support** (e.g. `tcp port 80`, `udp`, `host 8.8.8.8`)
- 💾 **PCAP export** — open your capture later in Wireshark
- 🌈 **Colored CLI output** (Windows / Linux / macOS via `colorama`)

---

## 📁 Project structure

```
CodeAlpha_NetworkSniffer/
├── sniffer.py            # CLI entry point
├── requirements.txt
├── README.md
└── src/
    ├── __init__.py
    ├── parser.py         # Packet dissection
    ├── stats.py          # Capture statistics
    └── display.py        # Colored terminal output
```

---

## ⚙️ Installation

```bash
git clone https://github.com/<your-username>/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
pip install -r requirements.txt
```

### 🪟 Windows only
Scapy needs a raw-packet driver. Install **[Npcap](https://npcap.com/#download)** and enable *WinPcap API-compatible Mode* during setup.

### 🐧 Linux / macOS
No extra driver required — you'll just need to run the sniffer with **`sudo`** (raw sockets need elevated privileges).

---

## 🚀 Usage

```bash
# Default: sniff on auto-detected interface, no limit
sudo python sniffer.py

# Capture exactly 50 packets on eth0
sudo python sniffer.py -i eth0 -c 50

# Only HTTP traffic
sudo python sniffer.py -f "tcp port 80"

# Only DNS
sudo python sniffer.py -f "udp port 53"

# Save the capture to a .pcap file (openable in Wireshark)
sudo python sniffer.py -c 100 -o capture.pcap

# Hide payloads (useful for cleaner demos)
sudo python sniffer.py --no-payload
```

### CLI options

| Flag | Description |
|------|-------------|
| `-i, --interface` | Network interface (default: auto) |
| `-c, --count`     | Number of packets to capture (`0` = infinite) |
| `-f, --filter`    | [BPF filter](https://biot.com/capstats/bpf.html) string |
| `-o, --output`    | Save captured packets to a `.pcap` file |
| `--no-payload`    | Do not display packet payloads |

---

## 🖼️ Sample output

```
[#   3] HTTPS   192.168.1.14:54321  →  142.250.185.78:443   (74 B)
   ├─ TTL   : 64
   ├─ Flags : S
   ├─ Hex   : 45 00 00 3c 1c 46 40 00 40 06 ...
   └─ ASCII : E..<.F@.@. ...

═══════════ CAPTURE SUMMARY ═══════════
Total packets : 128
Total bytes   : 84,213

▸ Protocol distribution
    HTTPS         62  ( 48.4%)
    DNS           28  ( 21.9%)
    TCP           19  ( 14.8%)
    ...
```

---

## 🧠 What this project taught me

- How data is encapsulated across the OSI layers (frames → packets → segments)
- The difference between **BPF filters** and app-level filtering
- How Scapy exposes each protocol layer as a Python object
- Why raw-socket capture requires root/administrator privileges
- Reading and interpreting **hex dumps** and TCP flag combinations
- Detecting basic anomalies from a stats-based view (top talkers, unusual ports)

---

## ⚠️ Legal disclaimer

This tool is provided for **educational purposes only**, as part of the CodeAlpha Cyber Security Internship.  
Only sniff traffic on networks you own or have **explicit written authorization** to monitor. Unauthorized interception of communications is illegal in most countries.

---

## 👤 Author

Built for **[CodeAlpha](https://www.codealpha.tech/)** — Cyber Security Internship, Task 1.
