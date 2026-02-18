# tests/test_detection_engine.py

import unittest
import sys
import os
import time

# -----------------------------
# Fix imports for Windows / relative paths
# -----------------------------
# Add parent folder (NetGuard_IDS) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import DetectionEngine from core folder
from core.detection_engine import DetectionEngine

# -----------------------------
# Unit Tests
# -----------------------------
class TestDetectionEngine(unittest.TestCase):

    def setUp(self):
        """Create a fresh DetectionEngine before each test"""
        self.engine = DetectionEngine()

    def test_ignore_local_ips(self):
        """Ensure local IDS host and router are ignored"""
        local_ips = ["192.168.1.1", "192.168.227.1"]
        for ip in local_ips:
            result = self.engine.analyze_packet(ip, 80)
            self.assertIsNone(result, f"{ip} should be ignored by the IDS")

    def test_dos_detection(self):
        """Trigger a DoS alert by sending enough packets"""
        attacker_ip = "192.168.227.137"
        # Send enough packets to exceed DOS_THRESHOLD
        for _ in range(self.engine.__class__.__dict__.get('DOS_THRESHOLD', 100) + 1):
            result = self.engine.analyze_packet(attacker_ip, 80)
        alert, high_priority = result
        self.assertIn("DoS attack", alert)

    def test_portscan_detection(self):
        """Trigger a Port Scan alert by scanning multiple ports"""
        attacker_ip = "192.168.227.137"
        for port in range(1, self.engine.__class__.__dict__.get('PORTSCAN_THRESHOLD', 10) + 2):
            result = self.engine.analyze_packet(attacker_ip, port)
        alert, high_priority = result
        self.assertIn("Port Scan", alert)

    def test_safe_cloud_ips(self):
        """Ensure known cloud IPs are ignored"""
        safe_ips = ["13.107.0.1", "52.1.2.3", "151.101.1.1"]
        for ip in safe_ips:
            result = self.engine.analyze_packet(ip, 80)
            self.assertIsNone(result, f"{ip} should be ignored as safe cloud IP")

# -----------------------------
# Run Tests
# -----------------------------
if __name__ == "__main__":
    unittest.main()