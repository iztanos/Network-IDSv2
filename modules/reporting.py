import sqlite3
from collections import Counter
from datetime import datetime, timedelta

DB_PATH = "ids_logs.db"
REPORT_FILE = "ids_daily_report.log"

def generate_daily_report():
    # Calculate time window for today (UTC)
    now = datetime.utcnow()
    start = datetime(now.year, now.month, now.day)
    end = start + timedelta(days=1)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, ip, protocol, attack_type, ports FROM alerts
        WHERE timestamp >= ? AND timestamp < ?
    """, (start.isoformat(), end.isoformat()))
    rows = cursor.fetchall()
    conn.close()

    new_icmp_ips = set()
    port_scans_tcp = 0
    port_scans_udp = 0
    ip_alerts = Counter()
    port_counter = Counter()

    for ts, ip, protocol, attack_type, ports in rows:
        ip_alerts[ip] += 1
        if attack_type == "New ICMP Activity":
            new_icmp_ips.add(ip)
        if attack_type == "Port Scan":
            if protocol == "TCP":
                port_scans_tcp += 1
            elif protocol == "UDP":
                port_scans_udp += 1
        if ports:
            for p in ports.split(","):
                if p.isdigit():
                    port_counter[int(p)] += 1

    report_lines = [
        f"IDS Daily Report ({start.date()}):",
        f"New ICMP IPs detected: {len(new_icmp_ips)}",
        f"TCP Port Scans detected: {port_scans_tcp}",
        f"UDP Port Scans detected: {port_scans_udp}",
        "",
        "Top Suspicious IPs:",
    ]
    for ip, count in ip_alerts.most_common(5):
        report_lines.append(f"  {ip}: {count} alerts")

    report_lines.append("\nMost Probed Ports:")
    for port, count in port_counter.most_common(5):
        bar = "#" * min(count, 40)
        report_lines.append(f"  Port {port}: {count} {bar}")

    report = "\n".join(report_lines)
    print(report)
    with open(REPORT_FILE, "a") as f:
        f.write(report + "\n" + "-"*60 + "\n")
