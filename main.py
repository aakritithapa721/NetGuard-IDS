import threading
import random
import time
from core.detection_engine import DetectionEngine

engine = DetectionEngine()

def simulate_packets():
    ip = "192.168.1.10"
    while True:
        port = random.randint(1, 100)
        alert = engine.analyze_packet(ip, port)
        if alert:
            print(alert)
        time.sleep(0.2)

def monitor_other_ips():
    ip_list = ["192.168.1.11", "192.168.1.12"]
    while True:
        for ip in ip_list:
            port = random.randint(1, 100)
            alert = engine.analyze_packet(ip, port)
            if alert:
                print(alert)
        time.sleep(0.3)

# Create threads
thread1 = threading.Thread(target=simulate_packets)
thread2 = threading.Thread(target=monitor_other_ips)

thread1.start()
thread2.start()

thread1.join()
thread2.join()