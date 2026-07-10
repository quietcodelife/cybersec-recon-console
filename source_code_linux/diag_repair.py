#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, subprocess, time, core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

def run():
    core_config.clear_screen()
    print(f"{R}================================================================{RESET}")
    print(f"             {Y}LINUX NETWORK REPAIR{RESET}")
    print(f"{R}================================================================{RESET}")
    print(" [!] ROOT privileges (sudo) are required.")
    print(" Steps:")
    print(" 1. Restart the NetworkManager service")
    print(" 2. Refresh the DHCP lease (dhclient)")
    print(" 3. Flush DNS cache (resolvectl)")
    
    if input("\n Continue? (y/n): ").lower() != 'y': return

    steps = [
        ("Restarting NetworkManager...", "sudo systemctl restart NetworkManager"),
        ("Releasing DHCP lease...", "sudo dhclient -r"),
        ("Requesting new IP address (DHCP)...", "sudo dhclient"),
        ("Flush DNS (resolvectl)...", "resolvectl flush-caches"),
    ]

    print("")
    for desc, cmd in steps:
        print(f" [*] {desc:<40}", end="", flush=True)
        try:
            ret = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ret == 0: print(f" {G}[OK]{RESET}")
            else: print(f" {R}[SKIP]{RESET}")
            time.sleep(1)
        except: print(f" {R}[ERROR]{RESET}")

    print(f"\n {G}[DONE]{RESET} Check your network connection.{RESET}")
    input("\n Enter...")
