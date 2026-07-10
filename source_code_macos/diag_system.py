#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess

import core_config
import core_report
import core_utils


def ensure_commands(*command_names):
    missing = core_utils.missing_commands(*command_names)
    if missing:
        print(f" [ERROR] Missing required system tools: {', '.join(missing)}")
        input("\n Enter...")
        return False
    return True


def run_ipconfig():
    core_config.clear_screen()
    print(" [!] Collecting full network configuration (ifconfig, route, dns)...")
    if not ensure_commands("ifconfig", "networksetup"):
        return

    cmd = (
        "echo '--- INTERFEJSY ---'; ifconfig; "
        "echo '\n--- TRASY ---'; netstat -rn; "
        "echo '\n--- DNS ---'; scutil --dns"
    )
    res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
    print(res)
    core_report.save(res, "IPConfig_All_macOS")
    input("\n Enter...")


def run_netstat():
    while True:
        core_config.clear_screen()
        print("=== CONNECTION MONITOR (netstat) ===\n")
        print(" [1] Active TCP connections only")
        print(" [2] Listening ports")
        print(" [0] Back")
        if not ensure_commands("netstat"):
            return

        c = input("\n Selection: ")
        if c == "0":
            break

        core_config.clear_screen()
        if c == "1":
            cmd = "netstat -anv -p tcp | grep ESTABLISHED"
        else:
            cmd = "netstat -anv | grep LISTEN"

        res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
        print("-" * 80)
        print(res or "No data.")
        print("-" * 80)

        if input("\n [?] Save report? (y/n): ").lower() == "y":
            core_report.save(res or "No data.", "Netstat_macOS")
        input("\n Enter...")


def run_arp():
    core_config.clear_screen()
    print(" [!] Collecting ARP table (arp -an)...")
    if not ensure_commands("arp"):
        return
    res = subprocess.run(["arp", "-an"], capture_output=True, text=True).stdout
    print(res)
    core_report.save(res, "ARP_Table_macOS")
    input("\n Enter...")
