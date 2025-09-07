from scapy.all import ICMP, IP
from modules.database_manager import log_alert_to_db

seen_ips = set()

def process_icmp_packet(packet):
    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip not in seen_ips:
        seen_ips.add(src_ip)
        alert_data = {
            "ip": src_ip,
            "protocol": "ICMP",
            "attack_type": "New ICMP Activity",
            "description": f"New source IP {src_ip} detected sending ICMP traffic.",
            "ports": [],
            "severity": "low"
        }
        log_alert_to_db(alert_data)
