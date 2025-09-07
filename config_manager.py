import os
import config

_current_config = {
    "TCP_THRESHOLD": config.TCP_THRESHOLD,
    "UDP_THRESHOLD": config.UDP_THRESHOLD,
    "TIME_WINDOW": config.TIME_WINDOW,
    "SAFE_PORTS": config.SAFE_PORTS,
    "UDP_SAFE_PORTS": config.UDP_SAFE_PORTS,
    "DB_PATH": config.DB_PATH,
    "LOG_FILE": config.LOG_FILE,
    "PORT_RANGE": config.PORT_RANGE,
}

def override_config(cli_args=None):
    # Override with environment variables
    tcp_thr = os.getenv("IDS_TCP_THRESHOLD")
    udp_thr = os.getenv("IDS_UDP_THRESHOLD")
    time_win = os.getenv("IDS_TIME_WINDOW")
    safe_ports = os.getenv("IDS_SAFE_PORTS")
    udp_safe_ports = os.getenv("IDS_UDP_SAFE_PORTS")

    if tcp_thr is not None:
        _current_config["TCP_THRESHOLD"] = int(tcp_thr)
    if udp_thr is not None:
        _current_config["UDP_THRESHOLD"] = int(udp_thr)
    if time_win is not None:
        _current_config["TIME_WINDOW"] = int(time_win)
    if safe_ports is not None:
        _current_config["SAFE_PORTS"] = [int(p) for p in safe_ports.split(",") if p.isdigit()]
    if udp_safe_ports is not None:
        _current_config["UDP_SAFE_PORTS"] = [int(p) for p in udp_safe_ports.split(",") if p.isdigit()]

    # Override with CLI arguments if provided
    if cli_args:
        for key in ["TCP_THRESHOLD", "UDP_THRESHOLD", "TIME_WINDOW"]:
            if hasattr(cli_args, key.lower()):
                val = getattr(cli_args, key.lower())
                if val is not None:
                    _current_config[key] = val

def validate_config():
    assert _current_config["TCP_THRESHOLD"] > 0, "TCP_THRESHOLD must be > 0"
    assert _current_config["UDP_THRESHOLD"] > 0, "UDP_THRESHOLD must be > 0"
    assert _current_config["TIME_WINDOW"] > 0, "TIME_WINDOW must be > 0"
    for port in _current_config["SAFE_PORTS"] + _current_config["UDP_SAFE_PORTS"]:
        assert config.PORT_RANGE[0] <= port <= config.PORT_RANGE[1], f"Port {port} out of range"

def get_config():
    return _current_config
