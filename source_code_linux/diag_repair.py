#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import time

import core_config

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                   {Y}NETWORK REPAIR{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Guided Linux network stack refresh.")
    print(" [i] Root privileges may be requested by the operating system.\n")

    print(f" {G}>>> REPAIR PLAN{RESET}")
    print(" ----------------------------------------------------------------")
    print(" 1. Restart NetworkManager")
    print(" 2. Release DHCP lease")
    print(" 3. Request a new DHCP lease")
    print(" 4. Flush resolver cache")
    print(" ----------------------------------------------------------------")

    if input("\n Continue with repair actions? (y/n): ").strip().lower() != "y":
        return

    steps = [
        ("Restart NetworkManager", "sudo systemctl restart NetworkManager"),
        ("Release DHCP lease", "sudo dhclient -r"),
        ("Request DHCP lease", "sudo dhclient"),
        ("Flush DNS cache", "resolvectl flush-caches"),
    ]

    report_lines = ["NETWORK REPAIR :: Linux", ""]
    print()
    for description, command in steps:
        print(f" [*] {description:<24}", end="", flush=True)
        try:
            return_code = subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if return_code == 0:
                print(f" {G}[OK]{RESET}")
                report_lines.append(f"{description}: OK")
            else:
                print(f" {Y}[SKIP]{RESET}")
                report_lines.append(f"{description}: SKIP ({return_code})")
            time.sleep(0.8)
        except Exception as exc:
            print(f" {R}[ERROR]{RESET}")
            report_lines.append(f"{description}: ERROR ({exc})")

    print(f"\n {G}>>> REPAIR SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(" STATUS:         Completed")
    print(" NEXT STEP:      Re-check interface state and connectivity")
    print(" ----------------------------------------------------------------")

    input("\n Enter...")
