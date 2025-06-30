# PRODIGY_CS_05

# 📡 Educational Packet Sniffer

A minimal, command‑line packet sniffer built with **[Scapy](https://scapy.net/)**.  
It captures live traffic, prints a one‑line summary for each packet (timestamp, source IP, destination IP, protocol, payload preview) and can optionally dump everything to a **`.pcap`** file for Wireshark.

> **⚠️ Legal / Ethical Notice**  
> Use this tool **only** on networks you own or have **explicit written permission** to monitor.  
> Unauthorized packet interception is illegal in many jurisdictions.

---

## ✨ Features
* Live capture on any interface (Ethernet, Wi‑Fi, loopback, etc.).
* BPF filter support (`-f "tcp port 80"`).
* Protocol name mapping (TCP/UDP/ICMP) with graceful fallback to protocol numbers.
* Pretty ASCII payload peek (first 32 printable bytes).
* Optional packet limit (`-c`) and **pcap** output (`-o`).
* Runs on Linux, macOS, and Windows (with Npcap).

---

## 🖥️ Requirements
| Dependency | Minimum Version | Notes |
|------------|-----------------|-------|
| Python     | 3.8+            | Install from <https://python.org> |
| Scapy      | 2.5.x           | `pip install scapy` |
| **Linux / macOS** | — | Needs root privileges (`sudo`) for raw sockets |
| **Windows** | Npcap 1.x      | Install from <https://nmap.org/npcap/> · **tick “WinPcap API‑compatible mode”** |

---

## 🔧 Installation

```bash
# 1) Clone or download this repo
git clone https://github.com/your‑repo/packet‑sniffer.git
cd packet‑sniffer

# 2) Install Python deps
pip install -r requirements.txt        # requirements.txt just contains 'scapy'

# 3) Windows ONLY: Install Npcap (WinPcap‑compatible)
