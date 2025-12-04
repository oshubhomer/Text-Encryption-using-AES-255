# 🔐 AES-256-CBC Text & File Encryption Tool

A secure Python-based encryption and decryption utility built from scratch using the AES-256-CBC algorithm.  
Supports both text and file encryption with password-derived keys, random IV generation, and PKCS7 padding.

---

## ✨ Features
- AES-256-CBC encryption and decryption
- Encrypt and decrypt **text** or **files**
- **Random IV** for every encryption to increase security
- **SHA-256 password key derivation**
- **PKCS7 padding** to align data to AES block size
- Base64 representation for safe sharing
- Secure password input via `getpass`
- Interactive CLI menu

---

## 🧠 How It Works
| Step | Description |
|-------|-------------|
| Password → Key | Password converted into a 256-bit key using SHA-256 |
| IV Generation | Fresh random IV generated for each encryption |
| AES-CBC Mode | Encrypts 16-byte blocks with chaining |
| Base64 Output | Converts encrypted bytes to readable format |
| Reverse Process | Decryption reconstructs original data |

---

## 📦 Installation
### Requirements
- Python 3.8+
- PyCryptodome library

### Install dependencies
```bash
pip install pycryptodome
```

---

## 🚀 Usage
### Run the script
```bash
python encrypt_tool.py
```

### Menu Options
| Option | Description |
|--------|-------------|
| 1 | Encrypt text |
| 2 | Decrypt text |
| 3 | Encrypt file |
| 4 | Decrypt file |
| 5 | Exit |

---

## 📌 Example Output
```
Enter plaintext: Hello World
Enter password:
--- Encrypted (Base64) ---
a8736Db98H7k2bL+e2D8b98sH7YB6DkNsj=
--- Decrypted Text ---
Hello World
```

---

## 🛡 Security Notes
- AES-256 is highly secure and industry trusted
- Random IV prevents repeated patterns in ciphertext
- Password is never stored or transmitted
- For enterprise-grade security, use PBKDF2/Argon2 key stretching

---

## 🗂 Project Structure
```
├── encrypt_tool.py
└── README.md
```

---

## 📖 Learning Outcomes
- Symmetric encryption fundamentals
- CBC mode and IV purpose
- Secure key derivation & padding
- Real-world encryption implementation

---

## 🙌 Contributions
Pull requests and improvements are welcome.

---

## 📄 License
MIT License
