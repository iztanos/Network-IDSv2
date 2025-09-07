import argparse
from datetime import datetime
from scapy.all import sniff, TCP, UDP, ICMP, IP
from modules import tcp_processor, udp_processor, icmp_processor

def print_packet_summary(packet):
    ts = datetime.utcnow().isoformat()
    src_ip = packet[IP].src if packet.haslayer(IP) else None
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    protocol = None
    ports = []
    if packet.haslayer(TCP):
        protocol = "TCP"
        ports = [packet[TCP].sport, packet[TCP].dport]
    elif packet.haslayer(UDP):
        protocol = "UDP"
        ports = [packet[UDP].sport, packet[UDP].dport]
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    print(f"[{ts}] {protocol} {src_ip} -> {dst_ip} Ports: {ports} Summary: {packet.summary()}")

def main():
    parser = argparse.ArgumentParser(description="IDS Test Script")
    parser.add_argument("--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("--test-mode", action="store_true", help="Call processor functions in test mode")
    args = parser.parse_args()

    def packet_handler(packet):
        print_packet_summary(packet)
        if args.test_mode:
            if packet.haslayer(TCP):
                tcp_processor.process_tcp_packet(packet)
            elif packet.haslayer(UDP):
                udp_processor.process_udp_packet(packet)
            elif packet.haslayer(ICMP):
                icmp_processor.process_icmp_packet(packet)

    print(f"Sniffing on interface {args.interface} (Ctrl+C to stop)...")
    try:
        sniff(iface=args.interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nTest stopped by user.")

if __name__ == "__main__":
    main()
