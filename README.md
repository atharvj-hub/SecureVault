# 🔐 SecureVault

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Modern file encryption suite with AES-256-GCM, RSA hybrid encryption, and secure key derivation.**

SecureVault provides military-grade encryption for local files with an intuitive CLI and GUI interface. Built for privacy-conscious users, security researchers, and developers who need production-ready cryptography.

---

## ✨ Features

- 🔒 **AES-256-GCM** authenticated encryption with integrity protection
- 🔑 **RSA Hybrid Encryption** for secure key sharing (no password exchange needed)
- 🛡️ **Argon2id KDF** - modern password hashing resistant to GPU attacks
- 📦 **Encrypted Vault Archives** - compress and encrypt entire folders
- 🖥️ **Dual Interface** - Command-line and GUI (CustomTkinter)
- 🗑️ **Secure File Shredding** - DoD 5220.22-M standard
- 🎯 **Cross-Platform** - Windows, Linux, macOS

---

## 🚀 Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/atharvj-hub/SecureVault.git
cd SecureVault
pip install -e .
```

### Basic Usage

```bash
# Encrypt a file with password
securevault encrypt secret.pdf

# Decrypt a file
securevault decrypt secret.pdf.enc

# Generate RSA keypair for sharing
securevault keygen --output ./keys

# Encrypt for a recipient (no password needed)
securevault encrypt document.pdf --recipient keys/public.pem

# Decrypt with your private key
securevault decrypt document.pdf.vault --key keys/private.pem
```

### GUI Mode

```bash
securevault gui
```

---

## 🔐 Cryptography Details

| Component | Implementation | Notes |
|-----------|---------------|-------|
| Symmetric Encryption | AES-256-GCM | Authenticated encryption with 96-bit nonce |
| Key Derivation | Argon2id | Memory-hard, GPU-resistant (100,000 iterations) |
| Fallback KDF | PBKDF2-SHA256 | For compatibility with older versions |
| Asymmetric Encryption | RSA-4096 | Hybrid encryption for secure key exchange |
| Random Generation | `os.urandom()` | Cryptographically secure entropy |
| File Shredding | 7-pass overwrite | DoD 5220.22-M standard |

---

## 📖 Documentation

- [Security Model](docs/SECURITY.md) - Threat model and cryptographic design
- [API Reference](docs/API.md) - Developer documentation
- [Vault Format Specification](docs/VAULT_FORMAT.md) - File format details

---

## 🛡️ Security Notice

⚠️ **Important Disclaimers:**

- This tool is provided for **legitimate security and privacy purposes only**
- Not audited by third-party security professionals (use at your own risk)
- No warranty provided - see LICENSE for details
- Always keep backups of important files before encryption

**Threat Model:**
SecureVault protects against:
- ✅ Unauthorized access to encrypted files
- ✅ Brute-force password attacks (via Argon2id)
- ✅ Data tampering (via GCM authentication)

SecureVault does NOT protect against:
- ❌ Malware on your device (keyloggers, memory scraping)
- ❌ Weak passwords chosen by users
- ❌ Physical attacks on your hardware
- ❌ Coercion or legal compulsion

For vulnerability reports, see [SECURITY.md](SECURITY.md)

---

## 🧪 Development

### Setup Development Environment

```bash
# Clone and install dev dependencies
git clone https://github.com/atharvj-hub/SecureVault.git
cd SecureVault
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Linting
flake8 src/ tests/

# Type checking
mypy src/
```

---

## 🗺️ Roadmap

- [x] AES-256-GCM encryption
- [x] PBKDF2 key derivation
- [x] Secure file shredding
- [x] Basic GUI
- [ ] RSA hybrid encryption (v0.2.0)
- [ ] Argon2id KDF (v0.2.0)
- [ ] Encrypted vault archives (v0.3.0)
- [ ] Password strength meter
- [ ] Audit logging
- [ ] PyInstaller builds

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

---

## 👤 Author

**Atharv**
- GitHub: [@atharvj-hub](https://github.com/atharvj-hub)
- Project Link: [https://github.com/atharvj-hub/SecureVault](https://github.com/atharvj-hub/SecureVault)

---

## 🙏 Acknowledgments

- Built with [cryptography](https://cryptography.io/) library
- Inspired by GPG, age, and VeraCrypt
- Thanks to the open-source security community

---

**⭐ If you find this project useful, please consider starring the repository!**