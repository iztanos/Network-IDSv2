import logging
import json
import threading
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP

LOG_FILE = "ids_all_ips.log"
log_lock = threading.Lock()

# Configure logging to not interfere with JSON file writes
logging.basicConfig(level=logging.INFO)

def log_packet_data(packet):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": packet[IP].src if packet.haslayer(IP) else None,
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
        "protocol": None,
        "ports": [],
        "summary": str(packet.summary())
    }

    if packet.haslayer(TCP):
        log_entry["protocol"] = "TCP"
        log_entry["ports"] = [packet[TCP].sport, packet[TCP].dport]
    elif packet.haslayer(UDP):
        log_entry["protocol"] = "UDP"
        log_entry["ports"] = [packet[UDP].sport, packet[UDP].dport]
    elif packet.haslayer(ICMP):
        log_entry["protocol"] = "ICMP"

    with log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
