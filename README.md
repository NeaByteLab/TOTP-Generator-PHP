# 🔐 TOTP Generator PHP

Simple PHP CLI script to generate a TOTP secret, create an OTP Auth URL, and verify user input with 3 attempts. Compatible with Google Authenticator. *QR code display requires `qrencode` installed and working in your terminal.*

---

## ✨ Features
- Base32 secret generation
- OTP Auth URL generation
- Terminal QR code display (requires `qrencode`)
- TOTP token generation with time window tolerance
- User input verification with 3 tries

--- 

## 📦 Installation

### 📥 Clone Repository
```bash
git clone https://github.com/NeaByteLab/TOTP-Generator-PHP.git
cd TOTP-Generator-PHP
```

## 🔧 Requirements
- PHP >= 7.0
- qrencode (optional, for QR display)

## 🚀 Usage
```bash
php index.php
```

## ❗ Troubleshooting QR Code
- Ensure `qrencode` is installed: `brew install qrencode`
- Verify `qrencode` works: `echo 'test' | qrencode -t ANSIUTF8`
- Some terminals (e.g. basic Windows CMD) may not render ANSI QR codes correctly. Try iTerm2, Terminal, or compatible emulator.

---

## Example
```bash
Secret: B7YN4DGLBXLE7XL4YIFJMJXOYJLPNQB5

<QR code in terminal if supported>
█████████████████████████████████████████
█████████████████████████████████████████
████ ▄▄▄▄▄ ██▀▀▄▄ ▀▄█▄██▀█████ ▄▄▄▄▄ ████
████ █   █ █▀███ ▄█  ▀ █  ██▀█ █   █ ████
████ █▄▄▄█ █▄▄█▀▀ ▀▄█▄█▄▄▄█▄▀█ █▄▄▄█ ████
████▄▄▄▄▄▄▄█▄█ ▀▄▀ ▀ █▄▀▄█ █ █▄▄▄▄▄▄▄████
████▄ ▀█▀ ▄▄█ █▄▀█ ▀▀▄ ▀▄▀ █▄█▀▀  ▀▀█████
████ ▀██▄▀▄▄ ▀▄█▀ ▄█ █▄▀▄▄ ▀  ▄▀    █████
██████▄█ ▀▄█▄ █▄▄█▀██▄   █▀ █▀ ▄█▀▀▄ ████
████▄ ▀▄▀▀▄▀▀▀▀ ▄ ▀ ▄▀▄█▄▄▀██▀ ▄▀▀ ▄▀████
████ ▄▄▀▄▄▄▀▀▀▄▄▀▄▄▄ ▄█▀▀▀▄▀▄▄█▀▄██▀▀████
████▄█▄▀▀ ▄▄▀ ▀▄▀ ▄  ▀▀ █▄█ ▀ ▄ ▄▄ █▄████
████ ▄   ▀▄▄▄█ █▄█▄▀▄█▀▀▄█ ▀█ █▀ ▄█ █████
████ ██▄▀ ▄▀▄▀▄ ▄    ▄ ▀ ▄ ████▀ █▀ ▀████
████▄▄▄▄▄▄▄▄▀  █ ▄ ▄▄█ ▀█▀▄  ▄▄▄  ██▀████
████ ▄▄▄▄▄ █ ███ █▄▄ ▄▄█▄█   █▄█ ▄▀ ▀████
████ █   █ ██ ▄▀ ▀█ ██  ▀█▄█▄ ▄▄ ▀█▄ ████
████ █▄▄▄█ █▀▄ ▀█▄ ▀▄▄█ ▀█  ████▄▀▀▄▄████
████▄▄▄▄▄▄▄█▄█▄▄▄█▄▄▄▄█▄██▄█▄████▄█▄█████
█████████████████████████████████████████
█████████████████████████████████████████

Token: 581649
Enter OTP: 123456
 -> OTP Invalid
Enter OTP: 581649
 -> OTP Valid
```

---

## 📜 License
MIT License © 2025 [NeaByteLab](https://github.com/NeaByteLab)