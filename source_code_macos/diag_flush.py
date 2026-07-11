#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess

import core_config

C, Y, G, R, RESET = "\033[96m", "\033[93m", "\033[92m", "\033[91m", "\033[0m"


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                    {Y}DNS CACHE FLUSH{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Refreshing local resolver cache...\n")

    commands = [
        ["sudo", "dscacheutil", "-flushcache"],
        ["sudo", "killall", "-HUP", "mDNSResponder"],
    ]

    executed = []
    for command in commands:
        try:
            if subprocess.call(command, stderr=subprocess.DEVNULL) == 0:
                executed.append(" ".join(command))
        except Exception:
            pass

    print(f" {G}>>> FLUSH SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    if executed:
        print(" STATUS:         SUCCESS")
        print(f" ACTION COUNT:   {len(executed)}")
        print(" ACTIONS:")
        for item in executed:
            print(f" - {item}")
    else:
        print(" STATUS:         FAILED")
        print(" DETAILS:        Unable to refresh the local DNS cache.")

    input("\n Enter...")
