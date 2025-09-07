# Modular IDS Cybersecurity System
# Network-IDSv2


## Project Overview
This project is a modular Intrusion Detection System (IDS) designed for real-time network monitoring and cybersecurity threat detection. It analyzes TCP, UDP, and ICMP traffic, identifies suspicious activity, and provides actionable alerts and daily reports.

## Features
- Real-time packet monitoring and logging
- Detection of TCP/UDP port scans and new ICMP activity
- Configurable thresholds and safe ports
- Alerting via email and Slack (non-blocking)
- Daily summary reports with top threats and statistics
- Threat intelligence integration (extensible)
- Modular architecture for easy extension

## Installation
1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ids_project.git
   cd ids_project
   ```
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Set environment variables for alerts**
   - For email alerts:
     ```
     IDS_SMTP_SERVER, IDS_SMTP_PORT, IDS_SMTP_USER, IDS_SMTP_PASS, IDS_ALERT_EMAIL
     ```
   - For Slack alerts:
     ```
     IDS_SLACK_WEBHOOK
     ```

## Usage
Run the IDS from the CLI:
```bash
python main.py --interface eth0 --tcp-threshold 3 --udp-threshold 6 --time-window 15
```
Arguments:
- `--interface` : Network interface to sniff on (required)
- `--tcp-threshold` : TCP port scan threshold (default: 2)
- `--udp-threshold` : UDP port scan threshold (default: 5)
- `--time-window` : Time window in seconds (default: 10)
- `--test-mode` : Print packet info without alerting

## Modules Overview
- **modules/tcp_processor.py**: Detects TCP port scans.
- **modules/udp_processor.py**: Detects UDP port scans.
- **modules/icmp_processor.py**: Detects new ICMP activity.
- **modules/logging_manager.py**: Logs all packets in JSON format.
- **modules/database_manager.py**: Manages SQLite alert database.
- **modules/alert_manager.py**: Sends alerts via email and Slack.
- **modules/reporting.py**: Generates daily summary reports.

## Database Queries
Example: List all high severity alerts
```sql
SELECT * FROM alerts WHERE severity = 'high';
```
Example: Count alerts per IP
```sql
SELECT ip, COUNT(*) FROM alerts GROUP BY ip ORDER BY COUNT(*) DESC;
```
Example: Find most probed ports
```sql
SELECT ports FROM alerts WHERE attack_type = 'Port Scan';
```

## Testing
Use `test.py` to verify packet processing:
```bash
python test.py --interface eth0 --test-mode
```
Prints packet summaries and optionally calls processor functions.

## Contributing
To add new detection modules or alert methods:
- Create a new processor in `modules/`
- Register it in `main.py` and `ids_detector.py`
- Follow the modular design for easy integration

## License
