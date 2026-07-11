#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import core_config
import core_report

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def print_banner():
    print(f"{C}================================================================{RESET}")
    print(f"            {Y}WHOIS / DOMAIN REGISTRATION (RDAP){RESET}")
    print(f"{C}================================================================{RESET}\n")


def run():
    while True:
        core_config.clear_screen()
        print_banner()
        domain = input(" Domain (for example google.com) [0=back]: ").strip()
        if not domain or domain == "0":
            break

        print(f"\n [i] Retrieving RDAP data for {domain}...")

        try:
            import requests

            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    )
                },
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()
                created = "No data"
                expired = "No data"
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        created = event.get("eventDate", "No data")
                    if event.get("eventAction") == "expiration":
                        expired = event.get("eventDate", "No data")

                statuses = data.get("status", [])
                output = "\n".join(
                    [
                        ">>> RDAP SUMMARY",
                        " ----------------------------------------------------------------",
                        f" DOMAIN:         {domain.upper()}",
                        f" REGISTERED:     {created[:10]}",
                        f" EXPIRES:        {expired[:10]}",
                        f" HANDLE:         {data.get('handle', 'N/A')}",
                        f" STATUS:         {', '.join(statuses) if statuses else 'No data'}",
                        " ----------------------------------------------------------------",
                    ]
                )
                print(f"\n {G}{output}{RESET}")
                if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                    core_report.save(output, f"Whois_{domain}")
            elif response.status_code == 404:
                print(f"\n [MISS] Domain {domain} does not appear in the RDAP registry.")
            elif response.status_code == 403:
                print("\n [ERROR] Access forbidden by the RDAP source (403).")
            elif response.status_code == 429:
                print("\n [ERROR] Rate limit reached. Please retry later.")
            else:
                print(f"\n [ERROR] RDAP source returned status {response.status_code}.")
        except Exception as exc:
            print(f"\n [CONNECTION ERROR] {exc}")

        input("\n Enter...")
