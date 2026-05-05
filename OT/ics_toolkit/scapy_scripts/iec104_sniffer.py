#!/usr/bin/env python3
import argparse
from scapy.all import *
import re

# Regex
FLAG_RE = re.compile(rb"(coc2026|flag)\{[^}\r\n]{1,200}\}", re.IGNORECASE)

def packet_handler(pkt):
    if TCP in pkt and Raw in pkt:
        # IEC 104 default port is 2404
        if pkt[TCP].sport == 2404 or pkt[TCP].dport == 2404:
            payload = bytes(pkt[Raw].load)
            
            # IEC 104 APCI is 6 bytes. ASDU follows.
            # Flag might be in the ASDU information elements.
            
            found_flags = set()
            found_flags.update(FLAG_RE.findall(payload))
            
            if found_flags:
                print(f"\n[ALERT] Flag Found in IEC 104 Packet:")
                for f in found_flags:
                    print(f"   => {f.decode('ascii', errors='ignore')}")

def main():
    parser = argparse.ArgumentParser(description="Sniff IEC 60870-5-104 Traffic for Flags")
    parser.add_argument("--iface", help="Interface to sniff on")
    args = parser.parse_args()

    print("[*] Starting IEC 104 Sniffer on port 2404...")
    if args.iface:
        sniff(filter="tcp port 2404", prn=packet_handler, iface=args.iface, store=0)
    else:
        sniff(filter="tcp port 2404", prn=packet_handler, store=0)

if __name__ == "__main__":
    main()
