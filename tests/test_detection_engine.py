import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
import time
from core.detection_engine import DetectionEngine, SAFE_CLOUD_IPS, LOG_FILE

class TestDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DetectionEngine()
        # Remove old log file if exists
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)

    def test_dos_detection_trigger(self):
        """Test if DoS alert triggers when threshold is exceeded"""
        ip = "192.168.100.10"
        result = None
        for _ in range(self.engine.__class__.__dict__.get('DOS_THRESHOLD', 100) + 1):
            result = self.engine.analyze_packet(ip, port=80)
        self.assertIsNotNone(result)
        message, high_priority = result
        self.assertIn("DoS", message)
        self.assertTrue(high_priority)

    def test_portscan_detection_trigger(self):
        """Test if Port Scan alert triggers when multiple ports accessed"""
        ip = "192.168.100.20"
        result = None
        for port in range(1, self.engine.__class__.__dict__.get('PORTSCAN_THRESHOLD', 10) + 2):
            result = self.engine.analyze_packet(ip, port=port)
        self.assertIsNotNone(result)
        message, high_priority = result
        self.assertIn("Port Scan", message)
        self.assertFalse(high_priority)

    def test_safe_cloud_ip_ignored(self):
        """Ensure safe cloud IPs do not trigger alerts"""
        ip = SAFE_CLOUD_IPS[0] + "1.2.3"
        alert = self.engine.analyze_packet(ip, port=80)
        self.assertIsNone(alert)

    def test_alert_log_file_created(self):
        """Check that alerts are logged"""
        ip = "192.168.50.50"
        # Trigger DoS alert
        for _ in range(self.engine.__class__.__dict__.get('DOS_THRESHOLD', 100) + 1):
            self.engine.analyze_packet(ip, port=80)
        time.sleep(0.1)
        self.assertTrue(os.path.exists(LOG_FILE))

    def test_multiple_ips_alerts(self):
        """Test independent alerts for multiple IPs"""
        ip1 = "192.168.1.101"
        ip2 = "192.168.1.102"
        result1 = None
        result2 = None
        # Trigger DoS for ip1
        for _ in range(self.engine.__class__.__dict__.get('DOS_THRESHOLD', 100) + 1):
            result1 = self.engine.analyze_packet(ip1, port=80)
        # Trigger Port Scan for ip2
        for port in range(1, self.engine.__class__.__dict__.get('PORTSCAN_THRESHOLD', 10) + 2):
            result2 = self.engine.analyze_packet(ip2, port=port)
        self.assertIsNotNone(result1)
        self.assertIn("DoS", result1[0])
        self.assertIsNotNone(result2)
        self.assertIn("Port Scan", result2[0])

if __name__ == "__main__":
    unittest.main()