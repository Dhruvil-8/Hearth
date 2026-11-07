#!/usr/bin/env python3
"""
Hearth Live Defense & Zero-Day Verification Script.
Demonstrates:
  1. Standard DNS query resolution
  2. Zero-Day Algorithmic DGA C2 sinkholing (Shannon Entropy)
  3. Zero-Day DNS Tunneling / Exfiltration sinkholing
  4. Querying Hearth's REST API for real-time anomaly detection
"""

import socket
import sys
import json
import urllib.request

DNS_HOST = "127.0.0.1"
DNS_PORT = 53
API_URL = "http://127.0.0.1:7777/api/anomalies"

def build_dns_query(domain: str, qid: int = 0x1337) -> bytes:
    """Construct a raw DNS A-record query packet."""
    header = qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = b""
    for part in domain.split("."):
        encoded = part.encode("ascii")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00\x00\x01\x00\x01" # QTYPE=A, QCLASS=IN
    return header + question

def send_query(domain: str) -> str:
    """Send query to local Hearth DNS sinkhole and return resolved IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    query = build_dns_query(domain)
    try:
        sock.sendto(query, (DNS_HOST, DNS_PORT))
        resp, _ = sock.recvfrom(1024)
        if len(resp) >= 16:
            # Check answer IP at end of standard response
            ip_bytes = resp[-4:]
            return ".".join(str(b) for b in ip_bytes)
    except Exception as e:
        return f"Timeout/Error ({e})"
    finally:
        sock.close()
    return "Unknown"

def main():
    print("=" * 60)
    print("  HEARTH ZERO-DAY DEFENSE & SINKHOLE VERIFICATION")
    print("=" * 60)
    
    test_cases = [
        ("google.com", "Legitimate Domain (Should Pass)"),
        ("x89qzm3ak91lqwv7.biz", "Zero-Day Algorithmic DGA Domain (Should Sinkhole to 0.0.0.0)"),
        ("aW5mbzEyMzQ1Njc4OTA1MTYyNzM4NDk1MDE5Mjg0NzI5Mzg0NzI5Mzg0NzI5.tunnel.evil.com", "Zero-Day DNS Tunneling Exfiltration (Should Sinkhole to 0.0.0.0)"),
    ]

    for domain, desc in test_cases:
        print(f"\n[*] Testing: {desc}")
        print(f"    Domain: {domain}")
        res_ip = send_query(domain)
        status = "[SINKHOLED 0.0.0.0]" if res_ip == "0.0.0.0" else f"[RESOLVED {res_ip}]"
        print(f"    Result: {status}")

    print("\n[*] Checking Hearth REST API for detected anomalies...")
    try:
        req = urllib.request.Request(API_URL)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode())
            print(f"[+] Total Active Anomalies: {len(data)}")
            for a in data[-3:]:
                print(f"    - [{a.get('kind')}] {a.get('detail')}")
    except Exception as e:
        print(f"    (Hearth daemon HTTP dashboard not running at {API_URL}: {e})")

    print("\n[+] Verification script complete.")

if __name__ == "__main__":
    main()

