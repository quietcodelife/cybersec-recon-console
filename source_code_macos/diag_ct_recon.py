#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
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


def fetch_ct_entries(domain):
    query = urllib.parse.quote(f"%.{domain}")
    request = urllib.request.Request(
        f"https://crt.sh/?q={query}&output=json",
        headers={"User-Agent": "CyberSec-Recon-Console/1.0"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = response.read().decode("utf-8", errors="replace")
    if not payload.strip():
        return []
    return json.loads(payload)


def extract_names(entries, domain):
    names = set()
    for entry in entries:
        raw_names = entry.get("name_value", "")
        for item in raw_names.splitlines():
            cleaned = item.strip().lower().lstrip("*.")
            if cleaned and cleaned.endswith(domain):
                names.add(cleaned)
    return sorted(names)


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                {Y}CERTIFICATE TRANSPARENCY RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n Domain or URL [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            domain = normalize_domain(target)
            print(f"\n [i] Querying certificate transparency logs for {domain}...")

            entries = fetch_ct_entries(domain)
            names = extract_names(entries, domain)

            print(f"\n {G}>>> CT RECON SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" DOMAIN:         {domain}")
            print(f" CT ENTRIES:     {len(entries)}")
            print(f" UNIQUE NAMES:   {len(names)}")
            print(" ----------------------------------------------------------------")

            print(f"\n {Y}DISCOVERED HOSTNAMES:{RESET}")
            if names:
                for name in names[:40]:
                    print(f"  {G}- {name}{RESET}")
                if len(names) > 40:
                    print(f"  {Y}... plus {len(names) - 40} more entries{RESET}")
            else:
                print(f"  {R}- No CT hostnames discovered{RESET}")

            report_lines = [
                f"CERTIFICATE TRANSPARENCY RECON: {domain}",
                f"CT Entries: {len(entries)}",
                f"Unique Names: {len(names)}",
                "",
                "[Discovered Hostnames]",
                *(names or ["No CT hostnames discovered"]),
            ]

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "CT_Recon")

        except urllib.error.HTTPError as exc:
            print(f"\n {R}[HTTP ERROR]{RESET} {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            print(f"\n {R}[CONNECTION ERROR]{RESET} {exc}")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
