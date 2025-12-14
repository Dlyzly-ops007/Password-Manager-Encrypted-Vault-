import os
import json
import base64
import getpass
import secrets
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend

VAULT_FILE = "vault.enc"
SALT_FILE = "salt.bin"


# ---------------- PASSWORD GENERATOR ----------------
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(characters) for _ in range(length))


# ---------------- KEY GENERATION ----------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# ---------------- VAULT SETUP ----------------
def setup_vault():
    print("🔐 Setting up new vault")
    password = getpass.getpass("Create master password: ")
    confirm = getpass.getpass("Confirm master password: ")

    if password != confirm:
        print("❌ Passwords do not match.")
        return None, None

    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)

    key = derive_key(password, salt)
    fernet = Fernet(key)

    encrypted = fernet.encrypt(json.dumps({}).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

    print("✅ Vault created successfully.")
    return key, {}


# ---------------- LOAD VAULT ----------------
def load_vault():
    if not os.path.exists(VAULT_FILE):
        return setup_vault()

    password = getpass.getpass("Enter master password: ")

    try:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

        key = derive_key(password, salt)
        fernet = Fernet(key)

        with open(VAULT_FILE, "rb") as f:
            encrypted = f.read()

        decrypted = fernet.decrypt(encrypted)
        data = json.loads(decrypted.decode())

        return key, data

    except (InvalidToken, FileNotFoundError):
        print("❌ Incorrect password or corrupted vault.")
        return None, None


# ---------------- SAVE VAULT ----------------
def save_vault(key, data):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)


# ---------------- ACTIONS ----------------
def add_entry(data):
    site = input("Website/App name: ").strip()
    username = input("Username: ").strip()

    print("\nChoose password option:")
    print("1. Enter password manually")
    print("2. Generate strong password")

    choice = input("Choice (1/2): ").strip()

    if choice == "2":
        try:
            length = int(input("Password length (default 16): ") or 16)
        except ValueError:
            length = 16
        password = generate_password(length)
        print(f"🔑 Generated password: {password}")
    else:
        password = getpass.getpass("Password: ")

    data[site] = {
        "username": username,
        "password": password
    }

    print("✅ Entry added.")


def view_entries(data):
    if not data:
        print("📭 Vault is empty.")
        return

    for site, creds in data.items():
        print(f"\n🔹 {site}")
        print(f"   Username: {creds['username']}")
        print(f"   Password: {creds['password']}")


def delete_entry(data):
    site = input("Enter site name to delete: ").strip()
    if site in data:
        del data[site]
        print("🗑 Entry deleted.")
    else:
        print("❌ Entry not found.")


# ---------------- CLEAN EXIT (AUTO-LOCK) ----------------
def lock_and_exit(key, data):
    save_vault(key, data)
    key = None
    data.clear()
    print("🔒 Vault locked.")
    exit(0)


# ---------------- MAIN MENU ----------------
def main():
    key, data = load_vault()
    if not key:
        return

    while True:
        print("\n==== PASSWORD MANAGER ====")
        print("1. Add entry")
        print("2. View entries")
        print("3. Delete entry")
        print("4. Exit (Lock vault)")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_entry(data)
            save_vault(key, data)

        elif choice == "2":
            view_entries(data)

        elif choice == "3":
            delete_entry(data)
            save_vault(key, data)

        elif choice == "4":
            lock_and_exit(key, data)

        else:
            print("❌ Invalid choice.")


if __name__ == "__main__":
    main()
