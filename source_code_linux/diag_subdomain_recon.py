#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
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


def fetch_hostsearch(domain):
    request = urllib.request.Request(
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        headers={"User-Agent": "CyberSec-Recon-Console/1.0"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read().decode("utf-8", errors="replace")


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

            raw_data = fetch_hostsearch(domain)
            subdomains = parse_hostsearch(raw_data, domain)
            resolved = resolve_sample(subdomains)

            print(f"\n {G}>>> SUBDOMAIN SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" DOMAIN:         {domain}")
            print(f" DISCOVERED:     {len(subdomains)}")
            print(" ----------------------------------------------------------------")

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
                "",
                "[Resolved Sample]",
                *([f"{host} -> {ip_addr}" for host, ip_addr in resolved] or ["No sample available"]),
                "",
                "[Discovered Subdomains]",
                *([f"{host},{ip_addr}" for host, ip_addr in subdomains] or ["No passive subdomains discovered"]),
            ]

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Subdomain_Recon")

        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
