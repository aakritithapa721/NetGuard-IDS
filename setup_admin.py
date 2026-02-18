# setup_admin.py
import hashlib

username = input("Enter admin username: ").strip()
password = input("Enter admin password: ").strip()

password_hash = hashlib.sha256(password.encode()).hexdigest()

# Write to .env
with open(".env", "w") as f:
    f.write(f"ADMIN_USERNAME={username}\n")
    f.write(f"ADMIN_PASSWORD_HASH={password_hash}\n")

print("✅ Admin created successfully in .env!")