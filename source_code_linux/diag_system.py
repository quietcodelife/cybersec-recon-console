#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, subprocess, core_report, core_config
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
    print(" [!] Collecting full network configuration (ip addr, route, dns)...")
    if not ensure_commands("ip"):
        return
    
    cmd = "echo '--- ADRESY IP ---'; ip addr show; echo '\n--- TRASY (ROUTING) ---'; ip route show; echo '\n--- DNS (RESOLV.CONF) ---'; cat /etc/resolv.conf"
    cmd = "echo '--- IP ADDRESSES ---'; ip addr show; echo '\n--- ROUTES ---'; ip route show; echo '\n--- DNS (RESOLV.CONF) ---'; cat /etc/resolv.conf"
    res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
    
    print(res)
    core_report.save(res, "IPConfig_All_Linux")
    input("\n Enter...")

def run_netstat():
    while True:
        core_config.clear_screen()
        print("=== CONNECTION MONITOR (SS/Netstat) ===\n")
        print(" [1] Active connections only (ESTABLISHED)")
        print(" [2] All listening ports")
        print(" [0] Back")
        if not ensure_commands("ss"):
            return
        
        c = input("\n Selection: ")
        if c == '0': break
        
        core_config.clear_screen()
        if c == '1':
            print(" [i] Active TCP sessions (ss -tun state established)...\n")
            cmd = 'ss -tun state established'
        else:
            print(" [i] Listening ports (ss -tuln)...\n")
            cmd = 'ss -tuln'

        res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
        
        print("-" * 80)
        print(res)
        print("-" * 80)
        
        if input("\n [?] Save report? (y/n): ").lower() == 'y':
            core_report.save(res, "Netstat_Linux")
        
        input("\n Enter...")

def run_arp():
    core_config.clear_screen()
    print(" [!] Collecting neighbor table (ARP / ip neigh)...")
    if not ensure_commands("ip"):
        return
    res = subprocess.run("ip neigh", capture_output=True, text=True, shell=True).stdout
    print(res)
    core_report.save(res, "ARP_Table_Linux")
    input("\n Enter...")
