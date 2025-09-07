import sqlite3
from datetime import datetime

DB_PATH = "ids_logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            description TEXT,
            ports TEXT,
            severity TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_alert_to_db(alert_data: dict):
    """
    Insert a new alert into the alerts table.
    alert_data keys: ip, protocol, attack_type, description, ports, severity
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.utcnow().isoformat()
    ports_str = ",".join(str(p) for p in alert_data.get("ports", []))
    cursor.execute("""
        INSERT INTO alerts (timestamp, ip, protocol, attack_type, description, ports, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        alert_data.get("ip"),
        alert_data.get("protocol"),
        alert_data.get("attack_type"),
        alert_data.get("description"),
        ports_str,
        alert_data.get("severity")
    ))
    conn.commit()
    conn.close()

# Initialize DB on import
init_db()
