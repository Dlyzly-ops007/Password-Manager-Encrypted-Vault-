# Password-Manager-Encrypted-Vault-
# 🔐 Password Manager (Python)

A simple local password manager that securely stores credentials using encryption.
All data is encrypted and protected by a master password.

## Features
- Master password protected vault
- Strong encryption using Fernet (AES)
- Add, view, and delete credentials
- Passwords never stored in plain text
- Offline and lightweight

On first run:
- Create a master password
- Vault files are generated automatically

## Files
- `vault.enc` → Encrypted password storage
- `salt.bin` → Salt for key derivation

## Security Notes
- Master password is never stored
- Wrong password = vault cannot be decrypted
- Uses PBKDF2 with 100,000 iterations
