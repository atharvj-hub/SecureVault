# Security Policy

## 🛡️ Security Philosophy

SecureVault is designed for legitimate privacy and security purposes. This tool should never be used for illegal activities, malicious purposes, or to circumvent lawful access to data.

---

## 🔐 Cryptographic Design

### Encryption Standards

- **Symmetric Encryption:** AES-256-GCM (Galois/Counter Mode)
  - 256-bit keys
  - 96-bit random nonces (never reused)
  - Built-in authentication tags (128-bit)
  
- **Key Derivation:** 
  - **Primary:** Argon2id (memory-hard, GPU-resistant)
    - Memory: 64 MB
    - Iterations: 3
    - Parallelism: 4 threads
  - **Fallback:** PBKDF2-SHA256 (100,000 iterations)
  
- **Asymmetric Encryption:** RSA-4096 with OAEP padding
  - Used for hybrid encryption (encrypting AES session keys)
  - Private keys encrypted with user passphrase (AES-256-CBC)

### Random Number Generation

All cryptographic randomness is sourced from `os.urandom()`, which uses:
- Windows: `CryptGenRandom()`
- Linux/macOS: `/dev/urandom`

### Known Limitations

SecureVault does NOT protect against:

1. **Endpoint Compromise**
   - Malware, keyloggers, or memory scrapers on your device
   - Physical access to an unlocked system
   
2. **Weak User Behavior**
   - Reused or weak passwords
   - Unencrypted backups of files
   - Storing passwords insecurely
   
3. **Side-Channel Attacks**
   - Timing attacks (partially mitigated)
   - Power analysis
   - Acoustic cryptanalysis
   
4. **Legal/Physical Coercion**
   - This tool cannot protect against legal compulsion or physical threats

---

## 🚨 Vulnerability Reporting

If you discover a security vulnerability in SecureVault, please report it responsibly:

### Reporting Process

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email: **[atharvj.one@gmail.com]** with subject line: `[SECURITY] SecureVault Vulnerability`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any proof-of-concept code

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Fix & Disclosure:** Coordinated disclosure after patch is ready

### Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be credited here (with permission):

*No vulnerabilities reported yet.*

---

## 🔍 Security Audit Status

- **Last Internal Review:** [November_10]
- **Third-Party Audit:** Not yet conducted
- **Penetration Testing:** Not yet conducted

⚠️ **Important:** This project has not undergone formal security auditing. Use at your own risk for non-critical applications.

---

## 📋 Security Checklist

Current security measures implemented:

- [x] AES-256-GCM authenticated encryption
- [x] Cryptographically secure random number generation
- [x] PBKDF2 key derivation (100,000 iterations)
- [x] Secure file shredding (7-pass DoD standard)
- [x] Memory zeroing for sensitive data (best-effort)
- [ ] Argon2id key derivation (planned v0.2.0)
- [ ] RSA hybrid encryption (planned v0.2.0)
- [ ] Constant-time comparisons for all auth checks
- [ ] Full memory protection (mlock, mprotect)
- [ ] Side-channel attack mitigation

---

## 🏛️ Legal & Compliance

### Intended Use

SecureVault is intended for:
- ✅ Personal data protection
- ✅ Secure file sharing between consenting parties
- ✅ Privacy research and education
- ✅ Compliance with data protection regulations (GDPR, CCPA)

### Prohibited Use

SecureVault must NOT be used for:
- ❌ Illegal activities or criminal purposes
- ❌ Hiding evidence from lawful investigations
- ❌ Circumventing employer monitoring (without authorization)
- ❌ Distributing malware or illegal content
- ❌ Any activity that violates local, state, or federal laws

### Export Compliance

This software may be subject to export control regulations. Users are responsible for complying with applicable laws in their jurisdiction.

---

## 📚 Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Guidelines on Cryptography](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Python Cryptography Documentation](https://cryptography.io/en/latest/)

---

**Last Updated:** November 2024