# main.py
from security.auth import login
import gui_dashboard  # This runs the Tkinter GUI after successful login

# Require admin login first
if not login():
    exit()  # Stop program if login fails

# After login, gui_dashboard.py opens the Tkinter window
# It handles traffic simulation and displays alerts