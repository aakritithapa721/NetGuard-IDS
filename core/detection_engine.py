# core/detection_engine.py

import sys
import os
import time
from collections import defaultdict
from dotenv import load_dotenv

# Fix module path so 'security' can be found
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import encryption

# Load environment variables
load_dotenv()

# -------------------------------
# Configuration
# -------------------------------
LOG_FILE = "logs/alerts.log"
os.makedirs("logs", exist_ok=True)

# Thresholds
DOS_THRESHOLD = int(os.getenv("DOS_THRESHOLD", 100))
PORTSCAN_THRESHOLD = int(os.getenv("PORTSCAN_THRESHOLD", 10))
TIME_WINDOW = int(os.getenv("TIME_WINDOW", 10))
ALERT_COOLDOWN = int(os.getenv("ALERT_COOLDOWN", 5))

# IPs to ignore
IGNORED_IPS = [
    "192.168.227.1",  # Windows VM (your IDS host)
    "192.168.1.1"     # Router/Gateway
]

# Optional: Safe cloud IPs to ignore
SAFE_CLOUD_IPS = [
    "13.107.",
    "40.112.",
    "20.42.",
    "34.",
    "35.",
    "52.",
    "54.",
    "18.",
    "151.101.",
    "23.",
    "142.251."
]

# -------------------------------
# Logging Function
# -------------------------------
def log_alert(alert):
    """Encrypt and store alert to logs/alerts.log"""
    encrypted = encryption.encrypt_message(alert)
    with open(LOG_FILE, "ab") as f:
        f.write(encrypted + b"\n")

# -------------------------------
# Detection Engine
# -------------------------------
class DetectionEngine:
    """
    Tracks IP activity and detects DoS and Port Scan attacks
    """

    def __init__(self):
        self.ip_activity = defaultdict(list)
        self.port_activity = defaultdict(set)
        self.last_alert_time = defaultdict(float)

    def analyze_packet(self, ip, port):

        # Ignore local IDS host and router
        if ip in IGNORED_IPS:
            return None

        # Ignore safe cloud IPs
        if any(ip.startswith(prefix) for prefix in SAFE_CLOUD_IPS):
            return None

        current_time = time.time()
        alert_message = None

        # -------------------------------
        # DoS Detection
        # -------------------------------
        self.ip_activity[ip].append(current_time)
        # Keep only packets within TIME_WINDOW seconds
        self.ip_activity[ip] = [
            t for t in self.ip_activity[ip] if current_time - t <= TIME_WINDOW
        ]

        if len(self.ip_activity[ip]) > DOS_THRESHOLD:
            if current_time - self.last_alert_time.get((ip, "DOS"), 0) > ALERT_COOLDOWN:
                alert_message = f"[ALERT] Possible DoS attack from {ip}"
                self.last_alert_time[(ip, "DOS")] = current_time

        # -------------------------------
        # Port Scan Detection
        # -------------------------------
        if port > 0:
            self.port_activity[ip].add(port)

        if len(self.port_activity[ip]) > PORTSCAN_THRESHOLD:
            if current_time - self.last_alert_time.get((ip, "PORTSCAN"), 0) > ALERT_COOLDOWN:
                alert_message = f"[ALERT] Possible Port Scan from {ip}"
                self.last_alert_time[(ip, "PORTSCAN")] = current_time

        # -------------------------------
        # Log and Return Alert
        # -------------------------------
        if alert_message:
            log_alert(alert_message)
            high_priority = "DoS" in alert_message
            return alert_message, high_priority

        return None