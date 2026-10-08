#!/usr/bin/env python3
"""
SSL/TLS Security & Certificate Inspector
Audits SSL/TLS certificate validity, expiration dates, supported protocol versions,
and flags weak security configurations.
"""

import argparse
import datetime
import socket
import ssl
import sys
from typing import Dict, Any, List

def check_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Retrieve and parse SSL certificate details from the target host."""
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "status": "SUCCESS",
                    "cert": cert,
                    "active_cipher": cipher,
                    "negotiated_tls": version
                }
    except ssl.SSLError as e:
        return {"status": "SSL_ERROR", "error": str(e)}
    except socket.timeout:
        return {"status": "TIMEOUT", "error": f"Connection to {hostname}:{port} timed out."}
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

def audit_tls_versions(hostname: str, port: int = 443) -> List[str]:
    """Check support for legacy/deprecated TLS versions (TLS 1.0, TLS 1.1)."""
    deprecated_versions = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    }
    
    supported_legacy = []
    
    for name, version in deprecated_versions.items():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = version
        ctx.minimum_version = version
        
        try:
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    supported_legacy.append(name)
        except Exception:
            pass  # Connection rejected = good (deprecated protocol not supported)
            
    return supported_legacy

def run_security_audit(hostname: str, port: int = 443):
    """Run full security audit and print detailed findings."""
    print("=" * 65)
    print(f"  SSL/TLS SECURITY INSPECTOR REPORT: {hostname}:{port}")
    print("=" * 65)

    res = check_ssl_certificate(hostname, port)

    if res["status"] != "SUCCESS":
        print(f"[-] Audit Failed: {res['error']}")
        return

    cert = res["cert"]
    cipher_name, tls_ver, secret_bits = res["active_cipher"]
    negotiated_tls = res["negotiated_tls"]

    # 1. Certificate Expiration Check
    not_after_str = cert.get("notAfter")
    expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
    days_remaining = (expiry_date - datetime.datetime.utcnow()).days

    print("\n[+] Certificate Info:")
    print(f"    Subject          : {dict(x[0] for x in cert.get('subject', []))}")
    print(f"    Issuer           : {dict(x[0] for x in cert.get('issuer', []))}")
    print(f"    Expiration Date  : {expiry_date.strftime('%Y-%m-%d')} ({days_remaining} days remaining)")

    # Expiration Risk Assessment
    if days_remaining < 0:
        print("    [!] ALERT: Certificate is EXPIRED!")
    elif days_remaining < 15:
        print("    [!] WARNING: Certificate expires in less than 15 days!")
    else:
        print("    [*] Certificate status: VALID")

    # 2. Connection Cipher & Protocol
    print("\n[+] Active Connection Details:")
    print(f"    Negotiated TLS   : {negotiated_tls}")
    print(f"    Active Cipher    : {cipher_name} ({secret_bits}-bit encryption)")

    # 3. Deprecated Protocol Audit
    print("\n[+] Auditing Deprecated TLS Support...")
    legacy = audit_tls_versions(hostname, port)
    
    if legacy:
        print(f"    [!] VULNERABILITY: Server supports insecure protocol(s): {', '.join(legacy)}")
    else:
        print("    [*] PASS: Server rejected legacy TLS 1.0 and TLS 1.1 connections.")

    print("\n" + "=" * 65)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit SSL/TLS Security for a domain.")
    parser.add_argument("target", help="Target domain (e.g., github.com or google.com)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")
    args = parser.parse_args()

    run_security_audit(args.target, args.port)
