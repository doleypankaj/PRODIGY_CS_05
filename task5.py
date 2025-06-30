import argparse
from datetime import datetime
import textwrap

from scapy.all import (
    conf,
    sniff,
    wrpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Raw,
)

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

def proto_name(proto_num: int) -> str:
    """Map protocol numbers to human‑readable names where possible."""
    return PROTO_NAMES.get(proto_num, str(proto_num))

def payload_preview(pkt) -> str:
    """Return up to 32 printable ASCII chars from Raw payload."""
    if Raw in pkt:
        raw_bytes = bytes(pkt[Raw].load)
        printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes[:32])
        return printable
    return ''

def show_summary(pkt) -> None:
    """Pretty‑print a one‑line packet summary."""
    now = datetime.now().strftime('%H:%M:%S')
    if IP in pkt:
        ip = pkt[IP]
        proto = proto_name(ip.proto)
        print(f"[{now}] {ip.src} -> {ip.dst} | {proto:<4} | {payload_preview(pkt)}")
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        proto = proto_name(ip.nh)
        print(f"[{now}] {ip.src} -> {ip.dst} | {proto:<4} | {payload_preview(pkt)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Educational Packet Sniffer built with Scapy")
    parser.add_argument("-i", "--iface", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-o", "--output", help="Write captured packets to this .pcap file")
    args = parser.parse_args()

    # If user didn’t supply an interface, stick with Scapy’s default.
    if args.iface:
        conf.iface = args.iface

    banner = textwrap.dedent(f"""
        ================================================
        Educational Packet Sniffer – {datetime.now():%Y-%m-%d}
        Interface : {conf.iface}
        Filter    : {args.filter or 'None'}
        Count     : {'∞' if args.count == 0 else args.count}
        ------------------------------------------------
        Press Ctrl+C to stop capturing.
        ================================================
    """)
    print(banner)

    # Do the sniff.
    packets = sniff(
        iface=conf.iface,
        filter=args.filter,
        prn=show_summary,
        store=bool(args.output),
        count=args.count or 0,
    )

    # Save to disk if requested.
    if args.output and packets:
        wrpcap(args.output, packets)
        print(f"\n[+] Saved {len(packets)} packets to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("[!] Permission denied – try running with sudo/Administrator rights.")
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
