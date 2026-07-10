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
    if core_utils.command_exists("pfctl"):
        sections.append(("PF RULES", *safe_run(["sudo", "pfctl", "-sr"])))
        sections.append(("PF STATUS", *safe_run(["sudo", "pfctl", "-s", "info"])))

    if not sections:
        print(f" {R}[ERROR]{RESET} No supported macOS firewall tools were found (`pfctl`).")
        input("\n Enter...")
        return

    risk_flags = []
    for title, _, output in sections:
        lowered = output.lower()
        if "status: disabled" in lowered:
            risk_flags.append(f"{title}: packet filter is disabled")
        if "no altq support in kernel" in lowered:
            risk_flags.append(f"{title}: kernel does not support parts of pf")

    print(f"\n {Y}SUMMARY:{RESET}")
    if risk_flags:
        for flag in risk_flags:
            print(f"  {R}[FLAG]{RESET} {flag}")
    else:
        print(f"  {G}[OK]{RESET} No obvious red flags were detected in this basic audit.")

    report_lines = ["FIREWALL AUDIT :: macOS", ""]
    for title, code, output in sections:
        status = f"{G}OK{RESET}" if code == 0 else f"{Y}WARN{RESET}"
        print(f"\n {C}--- {title} [{status}] ---{RESET}")
        lines = output.splitlines()
        for line in lines[:40]:
            print(line)
        if len(lines) > 40:
            print(f"... plus {len(lines) - 40} more lines")
        report_lines.append(f"[{title}] return_code={code}")
        report_lines.append(output)
        report_lines.append("")

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "Firewall_Audit_macOS")

    input("\n Enter...")
