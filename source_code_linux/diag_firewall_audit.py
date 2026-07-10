#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess

import core_config
import core_report
import core_utils

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'


def safe_run(command):
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return completed.returncode, completed.stdout.strip() or completed.stderr.strip() or "No data"


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                     {Y}FIREWALL AUDIT{RESET}")
    print(f"{C}================================================================{RESET}")

    sections = []

    if core_utils.command_exists("ufw"):
        code, output = safe_run(["ufw", "status", "verbose"])
        sections.append(("UFW STATUS", code, output))

    if core_utils.command_exists("nft"):
        code, output = safe_run(["nft", "list", "ruleset"])
        sections.append(("NFTABLES RULESET", code, output))

    if core_utils.command_exists("iptables"):
        code, output = safe_run(["iptables", "-S"])
        sections.append(("IPTABLES RULES", code, output))

    if not sections:
        print(f" {R}[ERROR]{RESET} No supported firewall tools were found (`ufw`, `nft`, `iptables`).")
        input("\n Enter...")
        return

    risk_flags = []
    for title, _, output in sections:
        lowered = output.lower()
        if "inactive" in lowered:
            risk_flags.append(f"{title}: firewall appears inactive")
        if "default: allow" in lowered or "policy accept" in lowered:
            risk_flags.append(f"{title}: default policy may be too permissive")

    print(f"\n {Y}SUMMARY:{RESET}")
    if risk_flags:
        for flag in risk_flags:
            print(f"  {R}[FLAG]{RESET} {flag}")
    else:
        print(f"  {G}[OK]{RESET} No obvious red flags were detected in this basic audit.")

    for title, code, output in sections:
        status = f"{G}OK{RESET}" if code == 0 else f"{Y}WARN{RESET}"
        print(f"\n {C}--- {title} [{status}] ---{RESET}")
        lines = output.splitlines()
        if lines:
            for line in lines[:40]:
                print(line)
            if len(lines) > 40:
                print(f"... plus {len(lines) - 40} more lines")
        else:
            print("No data.")

    report_lines = ["FIREWALL AUDIT", ""]
    if risk_flags:
        report_lines.append("[FLAGS]")
        report_lines.extend(risk_flags)
        report_lines.append("")

    for title, code, output in sections:
        report_lines.append(f"[{title}] return_code={code}")
        report_lines.append(output)
        report_lines.append("")

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "Firewall_Audit")

    input("\n Enter...")
