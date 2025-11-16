# SecureVault 

A Python-based AES-256 file encryption tool with advanced security features for secure file sharing and storage.

## Features

- **AES-256-GCM Encryption**: Industry-standard authenticated encryption
- **HMAC Authentication**: Alternative CBC mode with HMAC-SHA256
- **Secure Key Derivation**: PBKDF2 with 100,000+ iterations
- **File Shredding**: DoD 5220.22-M standard secure deletion
- **CLI & GUI**: Command-line and graphical interfaces
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Batch Processing**: Encrypt/decrypt multiple files

## Installation

\\\ash
pip install -r requirements.txt
\\\

## Quick Start

\\\ash
# Encrypt a file
python -m securevault encrypt myfile.pdf --password "your_password"

# Decrypt a file
python -m securevault decrypt myfile.pdf.enc --password "your_password"

# Secure shred a file
python -m securevault shred sensitive.txt --passes 7
\\\

## Documentation

See the [docs](docs/) directory for detailed documentation.

## License

MIT License - See LICENSE file for details

## Author

Your Name - B.Tech Mathematics & Computer Science
