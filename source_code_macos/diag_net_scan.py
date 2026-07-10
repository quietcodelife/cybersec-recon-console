#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import concurrent.futures
import subprocess
import time

import core_config
import core_mac_lookup
import core_utils
import db_wol


def wake_up_ip(ip):
    subprocess.run(["ping", "-c", "1", "-t", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def get_local_ip_prefix():
    adapters = core_config.get_adapters_info()
    for info in adapters.values():
        ip_addr = info.get("ip", "")
        if ip_addr and ip_addr != "---" and ip_addr.startswith(("10.", "172.", "192.168.")):
            return ".".join(ip_addr.split(".")[:-1]) + "."
    return "192.168.1."


def parse_arp_table(prefix):
    try:
        raw = subprocess.check_output(["arp", "-an"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []

    found = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        ip = parts[1].strip("()")
        mac = parts[3].upper()
        if not ip.startswith(prefix):
            continue
        if mac in ("(INCOMPLETE)", "INCOMPLETE"):
            continue
        vendor = core_mac_lookup.get_vendor(mac)
        found.append({"ip": ip, "mac": mac, "vendor": vendor})
    return found


def run():
    core_config.clear_screen()
    missing = core_utils.missing_commands("ping", "arp")
    if missing:
        print(f" [ERROR] Missing required system tools: {', '.join(missing)}")
        input("\n Enter...")
        return

    prefix = get_local_ip_prefix()
    print(f" [*] Scanning network {prefix}0/24 (ARP + ping sweep for macOS)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(wake_up_ip, [f"{prefix}{i}" for i in range(1, 255)]))

    found = parse_arp_table(prefix)
    print(f"\n {'ID':<4} | {'IP':<15} | {'MAC ADDRESS':<18} | {'VENDOR'}")
    print("-" * 80)
    for idx, item in enumerate(found, 1):
        print(f" [{idx:02}] | {item['ip']:<15} | {item['mac']:<18} | {item['vendor'][:30]}")

    if not found:
        print(" [i] No hosts were detected in the ARP table.")

    print("\n [A] Add to WOL database   [0] Back")
    choice = input("\n Selection: ").lower().strip()
    if choice != "a":
        return

    try:
        selected = int(input(" Device ID: ")) - 1
        if 0 <= selected < len(found):
            target = found[selected]
            name = input(f" Name (Enter={target['vendor'][:10]}): ").strip() or target["vendor"][:10]
            pwd = input(" Password: ").strip()
            db = db_wol.load_wol_profiles()
            db.append([name, target["mac"], target["ip"], pwd if pwd else "-"])
            db_wol.save_wol_profiles(db)
            print(" [OK] Added.")
            time.sleep(1)
    except Exception:
        pass
