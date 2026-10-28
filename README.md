# Secure File Encryption and Integrity Verification

Educational individual project using AES-256-GCM, Scrypt key derivation, and SHA-256.

## Setup
1. Install Python 3.10 or newer.
2. Create a virtual environment (recommended).
3. Run `pip install -r requirements.txt`.

## Commands
Encrypt: `python secure_file.py encrypt sample.txt sample.sfe --password "demo-password"`
Decrypt: `python secure_file.py decrypt sample.sfe recovered.txt --password "demo-password"`

Use a test password only for classroom demonstrations. Avoid placing real passwords in shell history or command-line arguments.

## Tests
Run: `python -m unittest -v`

## Limitations
This is a learning prototype, not a professionally audited product. It does not securely erase original files, provide a graphical interface, or protect a compromised computer. Passwords are supplied through the command line for demonstration convenience.
