# SSL/TLS Security & Cipher Inspect

A Python security auditing tool designed to inspect web server SSL/TLS certificates, evaluate cipher suite strength, and detect support for deprecated, vulnerable TLS protocols (TLS 1.0 / 1.1).

#Features
* **Certificate Lifecycle Audit:** Checks certificate issuer, validity, and remaining days until expiration.
* **Active Encryption Protocol Check:** Identifies the negotiated TLS version and active cipher bit strength.
* **Legacy TLS Detection:** Actively tests targets for support of deprecated TLS 1.0 and TLS 1.1 protocols.
* **Zero Dependencies:** Built entirely with standard Python libraries (`ssl`, `socket`, `argparse`).

# Usage

```bash
python3 ssl_inspector.py <domain_or_ip> [-p PORT]
# Verification & Audit Screenshots
# 1. Secure Target Audit
(Screenshot 2026-10-09 204820.png)
# 2. Output Export & Report Generation
Demonstrates running the security inspector against `google.com` and saving the generated audit report directly.
(Screenshot 2026-10-09 205024.png)
