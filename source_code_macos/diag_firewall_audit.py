#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess

import core_config
import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def safe_run(command):
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return completed.returncode, completed.stdout.strip() or completed.stderr.strip() or "No data"


def print_section(title, code, output):
    status = "OK" if code == 0 else "WARN"
    color = G if code == 0 else Y
    print(f"\n {color}>>> {title} [{status}]{RESET}")
    print(" ----------------------------------------------------------------")
    lines = output.splitlines()
    for line in lines[:30]:
        print(line)
    if len(lines) > 30:
        print(f"... plus {len(lines) - 30} more lines")


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
        print("\n [ERROR] No supported macOS firewall tool was found (pfctl).")
        input("\n Enter...")
        return

    risk_flags = []
    for title, _, output in sections:
        lowered = output.lower()
        if "status: disabled" in lowered:
            risk_flags.append("Packet filter is disabled")
        if "no altq support in kernel" in lowered:
            risk_flags.append("Kernel reports partial pf feature support")

    print(f"\n {G}>>> AUDIT SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" ENGINE:         pf")
    print(f" SECTIONS:       {len(sections)}")
    print(f" RISK FLAGS:     {len(risk_flags)}")
    print(" ----------------------------------------------------------------")

    if risk_flags:
        print("\n RISK FLAGS:")
        for flag in risk_flags:
            print(f" - {flag}")
    else:
        print("\n No obvious high-level firewall red flags were detected.")

    report_lines = ["FIREWALL AUDIT :: macOS", ""]
    if risk_flags:
        report_lines.extend(["[Risk Flags]", *risk_flags, ""])

    for title, code, output in sections:
        print_section(title, code, output)
        report_lines.extend([f"[{title}] return_code={code}", output, ""])

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "Firewall_Audit_macOS")
    input("\n Enter...")
