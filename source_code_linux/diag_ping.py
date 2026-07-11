#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess

import core_config
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

def run_menu():
    while True:
        core_config.clear_screen()
        print(f"{C}================================================================{RESET}")
        print(f"                        {Y}ICMP PROBE{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [1] Public DNS probe (4 packets)")
        print(" [2] Public DNS probe (continuous)")
        print(" [3] Custom target (4 packets)")
        print(" [4] Custom target (continuous)")
        print(" [0] Back")
        
        c = input("\n Selection: ")
        if c == '0':
            break
        
        try:
            if not core_utils.command_exists("ping"):
                raise RuntimeError("Missing required system command: 'ping'.")

            if c == '1':
                print("\n [i] Probing 8.8.8.8 with 4 ICMP packets...\n")
                subprocess.run(["ping", "-c", "4", "8.8.8.8"])
            elif c == '2':
                print("\n [i] Starting continuous ICMP probe to 8.8.8.8...\n")
                subprocess.run(["ping", "8.8.8.8"])
            elif c == '3': 
                adr = core_utils.validate_host(input(" Target host or IP: "))
                print(f"\n [i] Probing {adr} with 4 ICMP packets...\n")
                subprocess.run(["ping", "-c", "4", adr])
            elif c == '4': 
                adr = core_utils.validate_host(input(" Target host or IP: "))
                print(f"\n [i] Starting continuous ICMP probe to {adr}...\n")
                subprocess.run(["ping", adr])
            else:
                continue
            
            input("\n Enter...")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"\n {R}[ERROR]{RESET} {e}")
            input("\n Enter...")
