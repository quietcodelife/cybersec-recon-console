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
    print(" [i] Guided macOS resolver and cache refresh.")
    print(" [i] Root privileges may be requested by the operating system.\n")

    print(f" {G}>>> REPAIR PLAN{RESET}")
    print(" ----------------------------------------------------------------")
    print(" 1. Flush dscacheutil")
    print(" 2. Restart mDNSResponder")
    print(" 3. Refresh legacy resolver state")
    print(" ----------------------------------------------------------------")

    if input("\n Continue with repair actions? (y/n): ").strip().lower() != "y":
        return

    steps = [
        ("Flush dscacheutil", "sudo dscacheutil -flushcache"),
        ("Restart mDNSResponder", "sudo killall -HUP mDNSResponder"),
        ("Refresh resolver state", "sudo discoveryutil mdnsflushcache"),
    ]

    print()
    for description, command in steps:
        print(f" [*] {description:<24}", end="", flush=True)
        try:
            return_code = subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if return_code == 0:
                print(f" {G}[OK]{RESET}")
            else:
                print(f" {Y}[SKIP]{RESET}")
            time.sleep(0.8)
        except Exception:
            print(f" {R}[ERROR]{RESET}")

    print(f"\n {G}>>> REPAIR SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(" STATUS:         Completed")
    print(" NEXT STEP:      Re-check local name resolution and connectivity")
    print(" ----------------------------------------------------------------")

    input("\n Enter...")
