import argparse
from scapy.all import sniff, TCP, UDP, ICMP
from modules import logging_manager, database_manager, tcp_processor, udp_processor, icmp_processor

def main():
    parser = argparse.ArgumentParser(description="Modular IDS CLI")
    parser.add_argument("--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("--tcp-threshold", type=int, default=2, help="TCP port scan threshold")
    parser.add_argument("--udp-threshold", type=int, default=5, help="UDP port scan threshold")
    parser.add_argument("--time-window", type=int, default=10, help="Time window in seconds")
    parser.add_argument("--test-mode", action="store_true", help="Print packet info without alerting")
    args = parser.parse_args()

    # Set thresholds and time window in processors
    tcp_processor.PORT_SCAN_THRESHOLD = args.tcp_threshold
    tcp_processor.TIME_WINDOW = args.time_window
    udp_processor.PORT_SCAN_THRESHOLD = args.udp_threshold
    udp_processor.TIME_WINDOW = args.time_window

    print(f"Starting IDS on interface {args.interface} (Ctrl+C to stop)...")

    def packet_handler(packet):
        logging_manager.log_packet_data(packet)
        if args.test_mode:
            print(packet.summary())
            return
        if packet.haslayer(TCP):
            tcp_processor.process_tcp_packet(packet)
        elif packet.haslayer(UDP):
            udp_processor.process_udp_packet(packet)
        elif packet.haslayer(ICMP):
            icmp_processor.process_icmp_packet(packet)

    try:
        sniff(iface=args.interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nIDS stopped by user.")

if __name__ == "__main__":
    main()
