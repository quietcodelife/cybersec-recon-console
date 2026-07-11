import os
import re
import subprocess

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

DNS_SERVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "OpenDNS": "208.67.222.222",
    "Quad9": "9.9.9.9",
}


def print_banner():
    print(f"{C}================================================================{RESET}")
    print(f"                        {Y}DNS RECON{RESET}")
    print(f"{C}================================================================{RESET}")


def extract_records(response_text, resolver_ip):
    ipv4_matches = re.findall(r"Address(?:es)?:\s+((?:\d{1,3}\.){3}\d{1,3})", response_text)
    resolved_ipv4 = [item for item in ipv4_matches if item != resolver_ip]

    aliases = []
    for line in response_text.splitlines():
        lowered = line.lower().strip()
        if "canonical name" in lowered or "name =" in lowered:
            parts = line.split("=", 1)
            if len(parts) == 2:
                aliases.append(parts[1].strip())

    return resolved_ipv4, aliases


def print_quick_summary(domain, response_text):
    resolved_ipv4, aliases = extract_records(response_text, "8.8.8.8")

    print(f"\n {G}>>> DNS SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" TARGET:         {domain}")
    print(" PRIMARY DNS:    8.8.8.8")
    print(f" IPV4 RECORDS:   {len(resolved_ipv4)}")
    print(f" ALIASES:        {len(aliases)}")
    print(" ----------------------------------------------------------------")

    print("\n QUICK LOOKUP:")
    if resolved_ipv4:
        for ip_addr in resolved_ipv4:
            print(f" - {ip_addr}")
    else:
        print(" - No IPv4 records observed")

    if aliases:
        print("\n CNAME / ALIAS CHAIN:")
        for alias in aliases:
            print(f" - {alias}")


def print_propagation_table(results):
    print(f"\n {G}>>> PROPAGATION SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'RESOLVER':<12} {'IP':<15} {'RESULT'}")
    print(" " + "-" * 60)
    for name, ip_addr, result in results:
        print(f" {name:<12} {ip_addr:<15} {result}")


def run():
    while True:
        os.system("clear")
        print_banner()

        if not core_utils.command_exists("nslookup"):
            print("\n [ERROR] Missing required command: nslookup")
            input("\n Enter...")
            return

        raw_value = input("\n Domain or hostname (for example example.com) [0=back]: ").strip()
        if raw_value in ("", "0"):
            break

        try:
            domain = core_utils.validate_host(raw_value)
        except ValueError as exc:
            print(f"\n [ERROR] {exc}")
            input("\n Enter...")
            continue

        print(f"\n [i] Running resolver lookup for {domain}...\n")
        quick_response = subprocess.run(["nslookup", domain, "8.8.8.8"], capture_output=True, text=True)
        quick_output = quick_response.stdout.strip() or quick_response.stderr.strip() or "No response data."

        print_quick_summary(domain, quick_output)

        table_rows = []
        report_lines = [
            f"DNS reconnaissance for: {domain}",
            "",
            "[Quick Lookup Response]",
            quick_output,
            "",
            "[Propagation Summary]",
        ]

        for name, ip_addr in DNS_SERVERS.items():
            print(f" [*] Querying {name:<11} ({ip_addr:<15})...", end="", flush=True)
            try:
                response = subprocess.run(["nslookup", domain, ip_addr], capture_output=True, text=True).stdout
                resolved_ipv4, aliases = extract_records(response, ip_addr)
                findings = resolved_ipv4 or aliases
                if findings:
                    result = ", ".join(findings)
                    print(f" {G}OK{RESET}")
                else:
                    result = "No record"
                    print(f" {R}NO RECORD{RESET}")
            except Exception as exc:
                result = f"Error ({exc})"
                print(f" {R}ERROR{RESET}")

            table_rows.append((name, ip_addr, result))
            report_lines.append(f"{name} ({ip_addr}) -> {result}")

        print_propagation_table(table_rows)
        if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
            core_report.save("\n".join(report_lines), f"DNS_Recon_{domain}")
        input("\n Enter...")
