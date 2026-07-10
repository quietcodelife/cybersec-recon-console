#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, subprocess, concurrent.futures, time
import core_report, core_mac_lookup, core_config, db_wol
import core_utils

def wake_up_ip(ip):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_local_ip_prefix():
    try:
        if not core_utils.command_exists("ip"):
            raise FileNotFoundError
        res = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], stderr=subprocess.DEVNULL).decode().strip()
        parts = res.split()
        src_idx = parts.index("src") + 1
        ip_addr = parts[src_idx]
        return ".".join(ip_addr.split(".")[:-1]) + "."
    except: return "192.168.1."

def run():
    core_config.clear_screen()
    missing = core_utils.missing_commands("ping", "ip")
    if missing:
        print(f" [ERROR] Missing required system tools: {', '.join(missing)}")
        input("\n Enter...")
        return
    prefix = get_local_ip_prefix()
    print(f" [*] Scanning network {prefix}0/24 (ARP + ping sweep)...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(wake_up_ip, [f"{prefix}{i}" for i in range(1, 255)])

    try:
        raw = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode()
    except: raw = ""
    
    found = []
    print(f"\n {'ID':<4} | {'IP':<15} | {'MAC ADDRESS':<18} | {'PRODUCENT'}")
    print("-" * 80)
    
    # Format ip neigh: "192.168.1.1 dev eth0 lladdr aa:bb:cc... REACHABLE"
    lines = raw.strip().split('\n')
    idx = 1
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts:
            ip = parts[0]
            if not ip.startswith(prefix): continue
            
            mac_idx = parts.index("lladdr") + 1
            mac = parts[mac_idx].upper()
            
            vendor = core_mac_lookup.get_vendor(mac)
            print(f" [{idx:02}] | {ip:<15} | {mac:<18} | {vendor[:30]}")
            found.append({"ip": ip, "mac": mac, "vendor": vendor})
            idx += 1

    print("\n [A] Add to WOL database   [0] Back")
    choice = input("\n Selection: ").lower()
    
    if choice == 'a':
        try:
            sel = int(input(" Device ID: ")) - 1
            if 0 <= sel < len(found):
                t = found[sel]
                name = input(f" Name (Enter={t['vendor'][:10]}): ") or t['vendor'][:10]
                pwd = input(" Password: ")
                
                db = db_wol.load_wol_profiles()
                db.append([name, t['mac'], t['ip'], pwd if pwd else "-"])
                db_wol.save_wol_profiles(db)
                print(" [OK] Added."); time.sleep(1)
        except: pass
