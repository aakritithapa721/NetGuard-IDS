# NetGuard_IDS

NetGuard_IDS is a lightweight Intrusion Detection System (IDS) in Python.  
It detects **DoS attacks** and **Port Scans** on your network and provides a **Tkinter GUI dashboard** with live alerts.

---

## Features

- Real-time DoS & Port Scan detection
- Top-5 suspicious IPs tracking
- Alert sounds and visual highlights
- Encrypted logging
- Ignore specific IPs and filter alerts

---

## Requirements

- Python 3.14+
- [Nmap](https://nmap.org/) (install separately)
- Python packages:

```bash
pip install -r requirements.txt