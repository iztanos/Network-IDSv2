from scapy.all import TCP, IP
import time
from collections import defaultdict
from modules.database_manager import log_alert_to_db

SAFE_PORTS = {80, 443}
TIME_WINDOW = 10  # seconds
PORT_SCAN_THRESHOLD = 2

# Track: {src_ip: [(timestamp, dst_port), ...]}
packet_history = defaultdict(list)

def process_tcp_packet(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    if dst_port in SAFE_PORTS:
        return

    now = time.time()
    # Remove old entries
    packet_history[src_ip] = [
        (ts, port) for ts, port in packet_history[src_ip]
        if now - ts <= TIME_WINDOW
    ]
    # Add current packet
    packet_history[src_ip].append((now, dst_port))

    # Get unique unsafe ports accessed in window
    unique_ports = set(port for _, port in packet_history[src_ip])
    if len(unique_ports) > PORT_SCAN_THRESHOLD:
        alert_data = {
            "ip": src_ip,
            "protocol": "TCP",
            "attack_type": "Port Scan",
            "description": f"Source IP {src_ip} accessed {len(unique_ports)} unique unsafe ports in {TIME_WINDOW}s.",
            "ports": list(unique_ports),
            "severity": "medium"
        }
        log_alert_to_db(alert_data)
        # Clear history to avoid duplicate alerts
        packet_history[src_ip].clear()
