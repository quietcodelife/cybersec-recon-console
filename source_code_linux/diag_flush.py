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
        "resolvectl flush-caches",
        "systemd-resolve --flush-caches",
        "service nscd restart",
    ]

    executed = None
    for command in commands:
        try:
            if subprocess.call(command, shell=True, stderr=subprocess.DEVNULL) == 0:
                executed = command
                break
        except Exception:
            pass

    print(f" {G}>>> FLUSH SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    if executed:
        print(" STATUS:         SUCCESS")
        print(" METHOD:         Automatic fallback chain")
        print(f" ACTION:         {executed}")
    else:
        print(" STATUS:         NOT APPLICABLE")
        print(" DETAILS:        No supported local DNS cache service was detected.")

    input("\n Enter...")
