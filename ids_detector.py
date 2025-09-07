from scapy.all import sniff, TCP, UDP, ICMP
from modules import logging_manager, database_manager, tcp_processor, udp_processor, icmp_processor

def run_ids(interface, tcp_threshold=2, udp_threshold=5, time_window=10, test_mode=False):
    # Setup thresholds and time window
    tcp_processor.PORT_SCAN_THRESHOLD = tcp_threshold
    tcp_processor.TIME_WINDOW = time_window
    udp_processor.PORT_SCAN_THRESHOLD = udp_threshold
    udp_processor.TIME_WINDOW = time_window

    print(f"IDS started on interface {interface} (Ctrl+C to stop)...")

    def packet_handler(packet):
        try:
            logging_manager.log_packet_data(packet)
            if test_mode:
                print(packet.summary())
                return
            if packet.haslayer(TCP):
                tcp_processor.process_tcp_packet(packet)
            elif packet.haslayer(UDP):
                udp_processor.process_udp_packet(packet)
            elif packet.haslayer(ICMP):
                icmp_processor.process_icmp_packet(packet)
        except Exception as e:
            print(f"Error processing packet: {e}")

    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nIDS stopped by user.")
    except Exception as e:
        print(f"IDS error: {e}")