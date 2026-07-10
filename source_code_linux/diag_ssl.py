#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import ssl
from datetime import datetime, timezone

import core_report
import core_utils

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'


def format_subject(entries):
    flat = dict(item[0] for item in entries)
    return flat


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                      {Y}TLS DEEP AUDIT{RESET}")
        print(f"{C}================================================================{RESET}")

        host = input("\n Enter host (for example google.com) or [0] to return: ").strip()
        if host in ("", "0"):
            break

        try:
            host = core_utils.validate_host(host)
            print(f"\n [i] Initializing TLS handshake for {host}:443 ...")

            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=6) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
                    tls_version = tls_sock.version()

            issuer = format_subject(cert.get("issuer", []))
            subject = format_subject(cert.get("subject", []))

            issuer_name = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
            subject_name = subject.get("commonName", "Unknown")
            serial_number = cert.get("serialNumber", "No data")

            exp_raw = cert["notAfter"]
            exp_date = datetime.strptime(exp_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp_date - datetime.now(timezone.utc)).days

            alt_names = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
            self_signed = issuer == subject

            print(f"\n {G}>>> TLS PROFILE{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" HOST:           {C}{host}{RESET}")
            print(f" COMMON NAME:    {C}{subject_name}{RESET}")
            print(f" ISSUER:         {C}{issuer_name}{RESET}")
            print(f" TLS VERSION:    {Y}{tls_version}{RESET}")
            print(f" CIPHER:         {Y}{cipher[0] if cipher else 'No data'}{RESET}")
            print(f" CIPHER BITS:    {Y}{cipher[2] if cipher else 'No data'}{RESET}")
            print(f" SERIAL:         {serial_number}")
            print(f" EXPIRES:        {exp_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")

            if days_left < 0:
                print(f" STATUS:         {R}EXPIRED ({abs(days_left)} DAYS AGO){RESET}")
            elif days_left < 10:
                print(f" STATUS:         {R}CRITICAL ({days_left} DAYS LEFT){RESET}")
            elif days_left < 30:
                print(f" STATUS:         {Y}WARNING ({days_left} DAYS LEFT){RESET}")
            else:
                print(f" STATUS:         {G}VALID ({days_left} DAYS LEFT){RESET}")

            print(f" SELF-SIGNED:    {R if self_signed else G}{'YES' if self_signed else 'NO'}{RESET}")
            print(" ----------------------------------------------------------------")

            print(f"\n {Y}SUBJECT ALT NAMES:{RESET}")
            if alt_names:
                for name in alt_names[:12]:
                    print(f"  - {name}")
                if len(alt_names) > 12:
                    print(f"  ... plus {len(alt_names) - 12} more")
            else:
                print("  No SAN entries or no data.")

            report_txt = "\n".join([
                f"TLS DEEP AUDIT: {host}",
                f"Common Name: {subject_name}",
                f"Issuer: {issuer_name}",
                f"TLS Version: {tls_version}",
                f"Cipher: {cipher[0] if cipher else 'No data'}",
                f"Cipher Bits: {cipher[2] if cipher else 'No data'}",
                f"Serial: {serial_number}",
                f"Expires: {exp_date.isoformat()}",
                f"Days Left: {days_left}",
                f"Self-Signed: {'YES' if self_signed else 'NO'}",
                "SAN:",
                *[f"- {name}" for name in alt_names],
            ])
            if input("\n [?] Save results to file? (y/n): ").strip().lower() == 'y':
                core_report.save(report_txt, f"TLS_Audit_{host}")

        except socket.gaierror:
            print(f" {R}[ERROR]{RESET} Failed to resolve host name.")
        except ssl.SSLError as e:
            print(f" {R}[TLS ERROR]{RESET} {e}")
        except TimeoutError:
            print(f" {R}[TIMEOUT]{RESET} Host did not respond within the expected time.")
        except Exception as e:
            print(f" {R}[ERROR]{RESET} A problem occurred: {e}")

        input("\n Press Enter to check another host...")
