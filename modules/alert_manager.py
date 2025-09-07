import os
import threading
import smtplib
from email.mime.text import MIMEText
import requests
from datetime import datetime

def format_alert_message(alert_data):
    msg = (
        f"Timestamp: {datetime.utcnow().isoformat()}\n"
        f"Source IP: {alert_data.get('ip')}\n"
        f"Protocol: {alert_data.get('protocol')}\n"
        f"Attack Type: {alert_data.get('attack_type')}\n"
        f"Description: {alert_data.get('description')}\n"
        f"Ports: {', '.join(map(str, alert_data.get('ports', [])))}\n"
        f"Severity: {alert_data.get('severity')}\n"
    )
    return msg

def send_email_alert(alert_data):
    def _send():
        smtp_server = os.getenv("IDS_SMTP_SERVER")
        smtp_port = int(os.getenv("IDS_SMTP_PORT", "587"))
        smtp_user = os.getenv("IDS_SMTP_USER")
        smtp_pass = os.getenv("IDS_SMTP_PASS")
        recipient = os.getenv("IDS_ALERT_EMAIL")

        if not all([smtp_server, smtp_user, smtp_pass, recipient]):
            return

        subject = f"IDS Alert: {alert_data.get('attack_type')} ({alert_data.get('severity')})"
        body = format_alert_message(alert_data)
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_user
        msg["To"] = recipient

        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, [recipient], msg.as_string())
        except Exception:
            pass

    threading.Thread(target=_send, daemon=True).start()

def send_slack_alert(alert_data):
    def _send():
        webhook_url = os.getenv("IDS_SLACK_WEBHOOK")
        if not webhook_url:
            return
        message = format_alert_message(alert_data)
        payload = {"text": message}
        try:
            requests.post(webhook_url, json=payload, timeout=5)
        except Exception:
            pass

    threading.Thread(target=_send, daemon=True).start()
