#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def normalize_domain(raw_value):
    raw_value = (raw_value or "").strip()
    if not raw_value:
        raise ValueError("No domain was provided.")

    if "://" in raw_value:
        parsed = urllib.parse.urlparse(raw_value)
        raw_value = parsed.hostname or ""

    domain = core_utils.validate_host(raw_value).lower()
    return domain.lstrip("*.") if domain.startswith("*.") else domain


def fetch_hostsearch(domain, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
    request = urllib.request.Request(
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        headers={"User-Agent": "CyberSec-Recon-Console/1.0"},
    )
    with opener.open(request, timeout=15) as response:
        return {
            "body": response.read().decode("utf-8", errors="replace"),
            "tls_verified": verify_tls,
            "source_url": response.geturl(),
        }


def safe_fetch_hostsearch(domain):
    tls_note = None
    try:
        return fetch_hostsearch(domain, verify_tls=True), tls_note
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            tls_note = f"TLS validation failed for passive source: {reason}"
            return fetch_hostsearch(domain, verify_tls=False), tls_note
        raise


def parse_hostsearch(text, domain):
    results = []
    seen = set()
    for line in text.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != 2:
            continue
        host, ip_addr = parts
        host = host.lower()
        if host.endswith(domain) and host not in seen:
            results.append((host, ip_addr))
            seen.add(host)
    return results


def resolve_sample(results, limit=8):
    resolved = []
    for host, ip_addr in results[:limit]:
        try:
            resolved_ip = socket.gethostbyname(host)
        except Exception:
            resolved_ip = ip_addr or "Unresolved"
        resolved.append((host, resolved_ip))
    return resolved


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                   {Y}SUBDOMAIN RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n Domain or URL [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            domain = normalize_domain(target)
            print(f"\n [i] Querying passive subdomain source for {domain}...")

            result, tls_note = safe_fetch_hostsearch(domain)
            raw_data = result["body"]
            subdomains = parse_hostsearch(raw_data, domain)
            resolved = resolve_sample(subdomains)

            print(f"\n {G}>>> SUBDOMAIN SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" DOMAIN:         {domain}")
            print(f" DISCOVERED:     {len(subdomains)}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")

            if tls_note:
                print(f" {Y}[TLS NOTICE]{RESET} {tls_note}")
                print(f" {Y}[TLS NOTICE]{RESET} Passive collection continued in unverified certificate mode.")

            print(f"\n {Y}DISCOVERED SUBDOMAINS:{RESET}")
            if subdomains:
                for host, ip_addr in subdomains[:40]:
                    print(f"  {G}- {host}{RESET}  {C}{ip_addr}{RESET}")
                if len(subdomains) > 40:
                    print(f"  {Y}... plus {len(subdomains) - 40} more entries{RESET}")
            else:
                print(f"  {R}- No passive subdomains discovered{RESET}")

            report_lines = [
                f"SUBDOMAIN RECON: {domain}",
                f"Discovered: {len(subdomains)}",
                f"TLS Verify: {'OK' if result['tls_verified'] else 'BYPASS / UNVERIFIED'}",
                f"Passive Source URL: {result['source_url']}",
                "",
                "[Resolved Sample]",
                *([f"{host} -> {ip_addr}" for host, ip_addr in resolved] or ["No sample available"]),
                "",
                "[Discovered Subdomains]",
                *([f"{host},{ip_addr}" for host, ip_addr in subdomains] or ["No passive subdomains discovered"]),
            ]
            if tls_note:
                report_lines.extend(["", f"TLS Notice: {tls_note}"])

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Subdomain_Recon")

        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
