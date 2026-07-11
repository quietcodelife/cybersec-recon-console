#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess

import core_config
import core_utils

PATH = "/etc/hosts"
C, Y, G, R, RESET = "\033[96m", "\033[93m", "\033[92m", "\033[91m", "\033[0m"


def print_banner():
    print(f"{C}================================================================{RESET}")
    print(f"                     {Y}/ETC/HOSTS EDITOR{RESET}")
    print(f"{C}================================================================{RESET}")


def run():
    while True:
        core_config.clear_screen()
        print_banner()
        print(" [i] Local hostname overrides for testing and routing control.\n")
        print(" [1] View hosts file")
        print(" [2] Add entry (sudo)")
        print(" [3] Open in nano (sudo)")
        print(" [0] Back")

        choice = input("\n Selection: ").strip().lower()
        if choice == "0":
            break

        if choice == "1":
            try:
                with open(PATH, "r", encoding="utf-8") as file:
                    data = file.read().strip() or "File is empty."
                print(f"\n {G}>>> HOSTS CONTENT{RESET}")
                print(" ----------------------------------------------------------------")
                print(f" FILE:           {PATH}")
                print(" ----------------------------------------------------------------")
                print(data)
            except Exception as exc:
                print(f"\n [ERROR] {exc}")
            input("\n Enter...")
        elif choice == "2":
            try:
                ip_addr = core_utils.validate_ipv4(input(" IPv4 address: ").strip())
                domain = core_utils.validate_host(input(" Hostname: ").strip())
                line = f"{ip_addr} {domain}\n"
                result = subprocess.run(
                    ["sudo", "tee", "-a", PATH],
                    input=line,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode == 0:
                    print(f"\n {G}>>> UPDATE SUMMARY{RESET}")
                    print(" ----------------------------------------------------------------")
                    print(f" STATUS:         SUCCESS")
                    print(f" ENTRY:          {ip_addr} {domain}")
                else:
                    print(f"\n [ERROR] Failed to add entry: {result.stderr.strip()}")
            except Exception as exc:
                print(f"\n [ERROR] {exc}")
            input("\n Enter...")
        elif choice == "3":
            print("\n [i] Launching nano for manual editing...")
            subprocess.run(["sudo", "nano", PATH], check=False)
