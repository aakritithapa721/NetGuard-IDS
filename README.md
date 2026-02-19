# NetGuard IDS

NetGuard IDS is a mini Intrusion Detection System (IDS) built with Python.  
It detects DoS attacks and port scans on your network in real-time, with a graphical dashboard, live alerts, and secure logging.

## Features

- Detects **DoS attacks** and **port scanning**
- Live alerts with **Top 5 suspicious IPs**
- Graphical dashboard with **real-time charts**
- Option to **ignore IPs** and filter alert types
- **Unit tests included**
- **Encrypted logs** for alerts

## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/aakritithapa721/NetGuard-IDS.git
cd NetGuard-IDS
```

2. **Create and activate a virtual environment (recommended):**

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

3. **Install dependencies:**

```bash
python -m pip install -r requirements.txt
```

## Running the Tool

Run the IDS with the main dashboard:

```bash
python main.py
```

* The login window will appear. Use your configured admin credentials.
* After login, select the network interface to monitor.
* Start detection to see live alerts and real-time charts.

## Nmap Integration (Optional)

NetGuard IDS can optionally use the Nmap tool for advanced scanning.  

1. Place the Nmap executable (`nmap.exe`) inside:

```
tools/nmap/
```

2. Set the path in the code if needed:

```python
NMAP_PATH = "tools/nmap/nmap.exe"
```

Ran 5 tests in 0.159s

OK
```

