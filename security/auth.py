# security/auth.py
import os
import hashlib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get admin credentials from .env
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")  # SHA-256

# Function to hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Terminal login function (optional, can use GUI login instead)
def login():
    print("=== NetGuard IDS Admin Login ===")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    if username != ADMIN_USERNAME:
        print("❌ Invalid username.")
        return False
    if hash_password(password) != ADMIN_PASSWORD_HASH:
        print("❌ Invalid password.")
        return False

    print("✅ Login successful!")
    return True