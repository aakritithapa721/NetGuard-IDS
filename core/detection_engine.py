import time
from collections import defaultdict


class DetectionEngine:
    def __init__(self, dos_threshold=20, portscan_threshold=10, time_window=5):
        self.dos_threshold = dos_threshold
        self.portscan_threshold = portscan_threshold
        self.time_window = time_window

        self.ip_activity = defaultdict(list)
        self.port_activity = defaultdict(set)

    def analyze_packet(self, ip, port):
        current_time = time.time()

        # Store packet timestamp
        self.ip_activity[ip].append(current_time)

        # Remove old packets outside time window
        self.ip_activity[ip] = [
            t for t in self.ip_activity[ip]
            if current_time - t <= self.time_window
        ]

        # DoS Detection
        if len(self.ip_activity[ip]) > self.dos_threshold:
            return f"[ALERT] Possible DoS attack from {ip}"

        # Port Scan Detection
        self.port_activity[ip].add(port)

        if len(self.port_activity[ip]) > self.portscan_threshold:
            return f"[ALERT] Possible Port Scan from {ip}"

        return None