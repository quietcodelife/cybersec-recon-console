#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import ssl
import tempfile
import urllib.parse
import ipaddress
from datetime import datetime, timezone

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def parse_target(raw_target):
    raw_target = (raw_target or "").strip()
    if not raw_target:
        raise ValueError("No target was provided.")

    if "://" not in raw_target:
        raw_target = f"https://{raw_target}"

    parsed = urllib.parse.urlparse(raw_target)
    if not parsed.hostname:
        raise ValueError("Invalid target.")

    host = core_utils.validate_host(parsed.hostname)
    port = parsed.port or 443
    return host, port, parsed.geturl()


def format_name(entries):
    flat = {}
    for item in entries:
        if item:
            key, value = item[0]
            flat[key] = value
    return flat


def parse_cert_time(value):
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def decode_peer_cert(der_bytes):
    if not der_bytes:
        return {}

    pem_data = ssl.DER_cert_to_PEM_cert(der_bytes)
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as temp_cert:
        temp_cert.write(pem_data)
        temp_cert.flush()
        return ssl._ssl._test_decode_cert(temp_cert.name)


def dns_name_matches(host, pattern):
    host = (host or "").strip().lower().rstrip(".")
    pattern = (pattern or "").strip().lower().rstrip(".")
    if not host or not pattern:
        return False
    if "*" not in pattern:
        return host == pattern
    if not pattern.startswith("*."):
        return False

    suffix = pattern[2:]
    if not suffix or host == suffix or not host.endswith(f".{suffix}"):
        return False

    host_labels = host.split(".")
    suffix_labels = suffix.split(".")
    return len(host_labels) == len(suffix_labels) + 1


def certificate_matches_host(cert, host):
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    san_entries = cert.get("subjectAltName", [])
    dns_sans = [value for key, value in san_entries if key == "DNS"]
    ip_sans = [value for key, value in san_entries if key == "IP Address"]

    if is_ip:
        if ip_sans:
            return host in ip_sans
    else:
        if dns_sans:
            return any(dns_name_matches(host, pattern) for pattern in dns_sans)

    subject = format_name(cert.get("subject", []))
    common_name = subject.get("commonName", "")
    if is_ip:
        return host == common_name
    return dns_name_matches(host, common_name)


def collect_tls_profile(host, port, verify_tls=True):
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=8) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            if not cert:
                cert = decode_peer_cert(tls_sock.getpeercert(binary_form=True))
            cipher = tls_sock.cipher()
            tls_version = tls_sock.version()
            negotiated_alpn = tls_sock.selected_alpn_protocol()
            compression = tls_sock.compression()

    return {
        "cert": cert,
        "cipher": cipher,
        "tls_version": tls_version,
        "alpn": negotiated_alpn,
        "compression": compression,
        "tls_verified": verify_tls,
    }


def assess_risk(days_left, self_signed, hostname_match, tls_version, port):
    findings = []
    if days_left < 0:
        findings.append("Certificate expired")
    elif days_left < 15:
        findings.append("Certificate expiry is critical")
    elif days_left < 45:
        findings.append("Certificate expiry is approaching")

    if self_signed:
        findings.append("Certificate appears self-signed")
    if not hostname_match:
        findings.append("Certificate hostname mismatch")
    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append(f"Legacy TLS version negotiated: {tls_version}")
    if port != 443:
        findings.append(f"Service runs on non-standard TLS port: {port}")

    if not findings:
        findings.append("No immediate certificate risk flags detected")
    return findings


def print_list_section(title, values, ok_when_empty=False):
    print(f"\n {Y}{title}:{RESET}")
    if values:
        for value in values:
            print(f"  {G}- {value}{RESET}")
        return

    label = "No issues detected" if ok_when_empty else "No data available"
    color = G if ok_when_empty else R
    print(f"  {color}- {label}{RESET}")


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}TLS / CERTIFICATE INSPECTOR{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n Host or URL (for example example.com or https://example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            host, port, normalized_target = parse_target(target)
            tls_note = None
            try:
                result = collect_tls_profile(host, port, verify_tls=True)
            except ssl.SSLCertVerificationError as exc:
                tls_note = f"TLS validation failed: {exc}"
                result = collect_tls_profile(host, port, verify_tls=False)

            cert = result["cert"]
            issuer = format_name(cert.get("issuer", []))
            subject = format_name(cert.get("subject", []))
            issuer_name = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
            subject_name = subject.get("commonName", "Unknown")
            serial_number = cert.get("serialNumber", "No data")

            not_before = parse_cert_time(cert.get("notBefore"))
            not_after = parse_cert_time(cert.get("notAfter"))
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days if not_after else None
            age_days = max(0, (now - not_before).days) if not_before else None

            dns_sans = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
            ip_sans = [value for key, value in cert.get("subjectAltName", []) if key == "IP Address"]
            self_signed = issuer == subject

            hostname_match = certificate_matches_host(cert, host)

            risk_flags = assess_risk(days_left if days_left is not None else 9999, self_signed, hostname_match, result["tls_version"], port)

            if days_left is None:
                validity_state = f"{Y}UNKNOWN{RESET}"
                validity_text = "Unknown"
            elif days_left < 0:
                validity_state = f"{R}EXPIRED{RESET}"
                validity_text = f"{days_left} days left"
            elif days_left < 15:
                validity_state = f"{R}CRITICAL{RESET}"
                validity_text = f"{days_left} days left"
            elif days_left < 45:
                validity_state = f"{Y}WARNING{RESET}"
                validity_text = f"{days_left} days left"
            else:
                validity_state = f"{G}VALID{RESET}"
                validity_text = f"{days_left} days left"

            print(f"\n {G}>>> TLS CERTIFICATE SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" TARGET:         {normalized_target}")
            print(f" HOST:           {host}")
            print(f" PORT:           {port}")
            print(f" SUBJECT:        {subject_name}")
            print(f" ISSUER:         {issuer_name}")
            print(f" SERIAL:         {serial_number}")
            print(f" VALID FROM:     {not_before.strftime('%Y-%m-%d %H:%M:%S') + ' UTC' if not_before else 'No data'}")
            print(f" VALID UNTIL:    {not_after.strftime('%Y-%m-%d %H:%M:%S') + ' UTC' if not_after else 'No data'}")
            print(f" STATUS:         {validity_state} ({validity_text})")
            print(f" CERT AGE:       {str(age_days) + ' days' if age_days is not None else 'No data'}")
            print(f" HOSTNAME MATCH: {G if hostname_match else R}{'YES' if hostname_match else 'NO'}{RESET}")
            print(f" SELF-SIGNED:    {R if self_signed else G}{'YES' if self_signed else 'NO'}{RESET}")
            print(f" TLS VERSION:    {Y}{result['tls_version'] or 'Unknown'}{RESET}")
            print(f" CIPHER:         {Y}{result['cipher'][0] if result['cipher'] else 'No data'}{RESET}")
            print(f" CIPHER BITS:    {Y}{result['cipher'][2] if result['cipher'] else 'No data'}{RESET}")
            print(f" ALPN:           {result['alpn'] or 'Not negotiated'}")
            print(f" COMPRESSION:    {result['compression'] or 'None'}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")

            print_list_section("DNS SUBJECT ALT NAMES", dns_sans)
            print_list_section("IP SUBJECT ALT NAMES", ip_sans)
            print_list_section("RISK FLAGS", risk_flags, ok_when_empty=True)

            report_lines = [
                f"TLS / CERTIFICATE INSPECTOR: {normalized_target}",
                f"Host: {host}",
                f"Port: {port}",
                f"Subject: {subject_name}",
                f"Issuer: {issuer_name}",
                f"Serial: {serial_number}",
                f"Valid From: {not_before.isoformat() if not_before else 'No data'}",
                f"Valid Until: {not_after.isoformat() if not_after else 'No data'}",
                f"Days Left: {days_left if days_left is not None else 'No data'}",
                f"Certificate Age Days: {age_days if age_days is not None else 'No data'}",
                f"Hostname Match: {'YES' if hostname_match else 'NO'}",
                f"Self-Signed: {'YES' if self_signed else 'NO'}",
                f"TLS Version: {result['tls_version'] or 'Unknown'}",
                f"Cipher: {result['cipher'][0] if result['cipher'] else 'No data'}",
                f"Cipher Bits: {result['cipher'][2] if result['cipher'] else 'No data'}",
                f"ALPN: {result['alpn'] or 'Not negotiated'}",
                f"Compression: {result['compression'] or 'None'}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                "",
                "[DNS SAN]",
                *(dns_sans or ["No data available"]),
                "",
                "[IP SAN]",
                *(ip_sans or ["No data available"]),
                "",
                "[Risk Flags]",
                *risk_flags,
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Notice: {tls_note}"])

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "TLS_Certificate_Inspector")

        except socket.gaierror:
            print(f"\n {R}[DNS ERROR]{RESET} Failed to resolve the target host.")
        except TimeoutError:
            print(f"\n {R}[TIMEOUT]{RESET} The TLS endpoint did not respond in time.")
        except ssl.SSLError as exc:
            print(f"\n {R}[TLS ERROR]{RESET} {exc}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
