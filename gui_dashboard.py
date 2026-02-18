# gui_dashboard.py
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from security.auth import ADMIN_USERNAME, ADMIN_PASSWORD_HASH, hash_password
from core.detection_engine import DetectionEngine
import threading, os, sys, time
from collections import Counter, deque

from scapy.all import IP, TCP, UDP, sniff, get_if_list

# Matplotlib for charting
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ------------------------
# Cross-platform beep
# ------------------------
def play_alert_sound():
    def beep():
        if sys.platform.startswith("win"):
            import winsound
            winsound.Beep(1000, 300)
        else:
            print('\a', end='', flush=True)
    threading.Thread(target=beep, daemon=True).start()

# ------------------------
# Login check
# ------------------------
def check_login(username, password):
    return username.strip() == ADMIN_USERNAME.strip() and hash_password(password.strip()) == ADMIN_PASSWORD_HASH.strip()

# ------------------------
# Dashboard
# ------------------------
def open_dashboard():
    login_window.withdraw()
    dashboard = tk.Toplevel()
    dashboard.title("NetGuard IDS Dashboard")
    dashboard.geometry("950x750")

    # --- Interface selection ---
    tk.Label(dashboard, text="Select Network Interface:", font=("TkDefaultFont", 10, "bold")).pack(pady=(5,0))
    iface_var = tk.StringVar()
    iface_combo = ttk.Combobox(dashboard, textvariable=iface_var, values=get_if_list(), width=80)
    iface_combo.pack()
    iface_combo.current(0)  # default to first interface

    # --- Live summary ---
    summary_frame = tk.Frame(dashboard)
    summary_frame.pack(pady=5, fill='x')
    tk.Label(summary_frame, text="Top 5 Suspicious IPs:", font=("TkDefaultFont", 10, "bold")).pack(side='left', padx=5)
    summary_label = tk.Label(summary_frame, text="", fg="purple", font=("TkDefaultFont", 10))
    summary_label.pack(side='left', padx=5)

    # --- Filters / Ignore IPs ---
    filter_frame = tk.LabelFrame(dashboard, text="Filters / Ignore IPs")
    filter_frame.pack(fill='x', padx=10, pady=5)
    show_dos_var = tk.BooleanVar(value=True)
    show_port_var = tk.BooleanVar(value=True)
    tk.Checkbutton(filter_frame, text="Show DoS Alerts", variable=show_dos_var).pack(side='left', padx=5)
    tk.Checkbutton(filter_frame, text="Show Port Scan Alerts", variable=show_port_var).pack(side='left', padx=5)
    tk.Label(filter_frame, text="Ignore IPs (comma-separated):").pack(side='left', padx=5)
    ignore_ip_entry = tk.Entry(filter_frame, width=30)
    ignore_ip_entry.pack(side='left', padx=5)

    # --- Scrollable alert box ---
    global alert_box
    alert_box = scrolledtext.ScrolledText(dashboard, state='disabled', wrap='word', height=15)
    alert_box.pack(padx=10, pady=10, fill='both', expand=True)

    # --- Control buttons ---
    frame = tk.Frame(dashboard)
    frame.pack(pady=5)
    start_btn = tk.Button(frame, text="Start Detection")
    start_btn.pack(side='left', padx=5)
    stop_btn = tk.Button(frame, text="Stop Detection")
    stop_btn.pack(side='left', padx=5)
    clear_btn = tk.Button(frame, text="Clear Alerts")
    clear_btn.pack(side='left', padx=5)

    # --- Alert counters ---
    dos_label = tk.Label(dashboard, text="DoS Alerts: 0", fg="red")
    dos_label.pack(side='left', padx=10)
    port_label = tk.Label(dashboard, text="Port Scan Alerts: 0", fg="blue")
    port_label.pack(side='left', padx=10)

    dos_count = 0
    port_count = 0
    detection_running = True

    # Setup folders
    os.makedirs("logs", exist_ok=True)
    os.makedirs("logs/archive", exist_ok=True)

    engine = DetectionEngine()
    alert_queue = deque()
    ip_alert_counter = Counter()
    TOP5_LOG_FILE = "logs/top5_ips.log"
    if not os.path.exists(TOP5_LOG_FILE):
        with open(TOP5_LOG_FILE, "w") as f:
            f.write("NetGuard IDS Top-5 Suspicious IPs Log\n\n")

    # --- Matplotlib chart ---
    chart_window_size = 60
    dos_history = deque([0]*chart_window_size, maxlen=chart_window_size)
    port_history = deque([0]*chart_window_size, maxlen=chart_window_size)
    fig = Figure(figsize=(8,2.5))
    ax = fig.add_subplot(111)
    ax.set_title("Alerts Over Time (DoS vs Port Scan)")
    ax.set_xlabel("Batch Updates (~0.5s per)")
    ax.set_ylabel("Count")
    ax.set_ylim(0, 10)
    line_dos, = ax.plot(list(range(chart_window_size)), list(dos_history), color="red", label="DoS")
    line_port, = ax.plot(list(range(chart_window_size)), list(port_history), color="blue", label="Port Scan")
    ax.legend(loc="upper right")
    ax.grid(True)
    canvas = FigureCanvasTkAgg(fig, master=dashboard)
    canvas.get_tk_widget().pack(fill='x', padx=10, pady=5)
    canvas.draw()

    # --- Process alert queue ---
    def process_alert_queue():
        nonlocal dos_count, port_count
        dos_batch_count = 0
        port_batch_count = 0
        ignore_ips = [ip.strip() for ip in ignore_ip_entry.get().split(",") if ip.strip()]

        if alert_queue:
            batch = list(alert_queue)
            alert_queue.clear()
            alert_box.configure(state='normal')
            high_priority_ips = set()

            for alert, high_priority, ip, alert_type in batch:
                if ip in ignore_ips: continue
                if alert_type == "DoS" and not show_dos_var.get(): continue
                if alert_type == "PORTSCAN" and not show_port_var.get(): continue

                if "DoS" in alert:
                    dos_count += 1
                    dos_batch_count += 1
                    dos_label.config(text=f"DoS Alerts: {dos_count}")
                    alert_box.insert(tk.END, alert + "\n", "dos")
                    alert_box.tag_config("dos", foreground="red", font=("TkDefaultFont", 10, "bold"))
                    if high_priority: high_priority_ips.add(ip)
                elif "Port Scan" in alert:
                    port_count += 1
                    port_batch_count += 1
                    port_label.config(text=f"Port Scan Alerts: {port_count}")
                    alert_box.insert(tk.END, alert + "\n", "port")
                    alert_box.tag_config("port", foreground="blue", font=("TkDefaultFont", 10, "italic"))
                ip_alert_counter[ip] += 1

            alert_box.see(tk.END)
            alert_box.configure(state='disabled')

            if high_priority_ips:
                play_alert_sound()
                def flash(times):
                    if times > 0:
                        current_bg = alert_box.cget("background")
                        new_bg = "yellow" if current_bg == "white" else "white"
                        alert_box.config(background=new_bg)
                        alert_box.after(300, lambda: flash(times-1))
                    else:
                        alert_box.config(background="white")
                flash(6)

        # Update chart
        dos_history.append(dos_batch_count)
        port_history.append(port_batch_count)
        line_dos.set_ydata(list(dos_history))
        line_port.set_ydata(list(port_history))
        max_val = max(max(dos_history), max(port_history), 5)
        ax.set_ylim(0, max_val + 2)
        canvas.draw()

        # Update top-5
        top_ips = [ip for ip, _ in ip_alert_counter.most_common(5)]
        summary_label.config(text=", ".join(top_ips))

        dashboard.after(500, process_alert_queue)

    dashboard.after(500, process_alert_queue)

    # --- Sniffer ---
    def safe_packet_callback(packet):
        if detection_running and IP in packet:
            ip_src = packet[IP].src
            if TCP in packet:
                port = packet[TCP].sport
            elif UDP in packet:
                port = packet[UDP].sport
            else:
                port = 0

            if port > 0 and port <= 1024:
                result = engine.analyze_packet(ip_src, port)
                if result:
                    alert, high_priority = result
                    alert_type = "DoS" if "DoS" in alert else "PORTSCAN"
                    alert_queue.append((alert, high_priority, ip_src, alert_type))

    def start_sniffer():
        iface = iface_var.get()
        threading.Thread(
            target=lambda: sniff(iface=iface, prn=safe_packet_callback, store=False, filter="ip"),
            daemon=True
        ).start()

    # --- Logging ---
    def log_top5_ips():
        if ip_alert_counter:
            top_ips = ip_alert_counter.most_common(5)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] Top 5 Suspicious IPs:\n"
            for ip, count in top_ips:
                log_entry += f"  {ip} - {count} alerts\n"
            log_entry += "\n"
            with open("logs/top5_ips.log", "a") as f:
                f.write(log_entry)
        dashboard.after(60000, log_top5_ips)

    dashboard.after(60000, log_top5_ips)

    def backup_alert_log():
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        src_file = "logs/alerts.log"
        dest_file = f"logs/archive/alerts_{timestamp}.log"
        if os.path.exists(src_file):
            with open(src_file, "rb") as src, open(dest_file, "wb") as dst:
                dst.write(src.read())
        dashboard.after(3600000, backup_alert_log)

    dashboard.after(3600000, backup_alert_log)

    # --- Buttons ---
    def clear_alerts():
        alert_box.configure(state='normal')
        alert_box.delete(1.0, tk.END)
        alert_box.configure(state='disabled')
        nonlocal dos_count, port_count
        dos_count = 0
        port_count = 0
        dos_label.config(text=f"DoS Alerts: {dos_count}")
        port_label.config(text=f"Port Scan Alerts: {port_count}")
        ip_alert_counter.clear()
        summary_label.config(text="")
        alert_queue.clear()
        dos_history.clear()
        port_history.clear()
        dos_history.extend([0]*60)
        port_history.extend([0]*60)

    def stop_detection():
        nonlocal detection_running
        detection_running = False

    def start_detection_btn():
        nonlocal detection_running
        detection_running = True
        start_sniffer()  # start sniffing on selected interface

    clear_btn.config(command=clear_alerts)
    stop_btn.config(command=stop_detection)
    start_btn.config(command=start_detection_btn)

    dashboard.mainloop()

# ------------------------
# Login Window
# ------------------------
login_window = tk.Tk()
login_window.title("NetGuard IDS Login")
login_window.geometry("300x150")

tk.Label(login_window, text="Username:").pack(pady=(10,0))
username_entry = tk.Entry(login_window)
username_entry.pack()

tk.Label(login_window, text="Password:").pack(pady=(10,0))
password_entry = tk.Entry(login_window, show="*")
password_entry.pack()

tk.Button(login_window, text="Login", command=lambda: attempt_login()).pack(pady=10)

def attempt_login():
    username = username_entry.get()
    password = password_entry.get()
    if check_login(username, password):
        messagebox.showinfo("Login Successful", f"Welcome, {username}!")
        open_dashboard()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

login_window.mainloop()