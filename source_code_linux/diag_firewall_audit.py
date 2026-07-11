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
    if lines:
        for line in lines[:30]:
            print(line)
        if len(lines) > 30:
            print(f"... plus {len(lines) - 30} more lines")
    else:
        print("No data.")


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                     {Y}FIREWALL AUDIT{RESET}")
    print(f"{C}================================================================{RESET}")

    sections = []
    engines = []
    if core_utils.command_exists("ufw"):
        code, output = safe_run(["ufw", "status", "verbose"])
        sections.append(("UFW STATUS", code, output))
        engines.append("ufw")
    if core_utils.command_exists("nft"):
        code, output = safe_run(["nft", "list", "ruleset"])
        sections.append(("NFTABLES RULESET", code, output))
        engines.append("nftables")
    if core_utils.command_exists("iptables"):
        code, output = safe_run(["iptables", "-S"])
        sections.append(("IPTABLES RULES", code, output))
        engines.append("iptables")

    if not sections:
        print("\n [ERROR] No supported firewall tools were found (ufw, nft, iptables).")
        input("\n Enter...")
        return

    risk_flags = []
    for _, _, output in sections:
        lowered = output.lower()
        if "inactive" in lowered:
            risk_flags.append("Firewall appears inactive")
        if "default: allow" in lowered or "policy accept" in lowered:
            risk_flags.append("Default policy may be too permissive")

    print(f"\n {G}>>> AUDIT SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" ENGINES:        {', '.join(engines)}")
    print(f" SECTIONS:       {len(sections)}")
    print(f" RISK FLAGS:     {len(risk_flags)}")
    print(" ----------------------------------------------------------------")

    if risk_flags:
        print("\n RISK FLAGS:")
        for flag in risk_flags:
            print(f" - {flag}")
    else:
        print("\n No obvious high-level firewall red flags were detected.")

    report_lines = ["FIREWALL AUDIT :: Linux", ""]
    if risk_flags:
        report_lines.extend(["[Risk Flags]", *risk_flags, ""])

    for title, code, output in sections:
        print_section(title, code, output)
        report_lines.extend([f"[{title}] return_code={code}", output, ""])

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "Firewall_Audit_Linux")
    input("\n Enter...")
