#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import concurrent.futures
import subprocess
import time

import core_config
import core_mac_lookup
import core_utils
import db_wol

C, Y, G, R, RESET = "\033[96m", "\033[93m", "\033[92m", "\033[91m", "\033[0m"


def wake_up_ip(ip_addr):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip_addr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def get_local_ip_prefix():
    try:
        if not core_utils.command_exists("ip"):
            raise FileNotFoundError
        response = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], stderr=subprocess.DEVNULL).decode().strip()
        parts = response.split()
        source_index = parts.index("src") + 1
        ip_addr = parts[source_index]
        return ".".join(ip_addr.split(".")[:-1]) + "."
    except Exception:
        return "192.168.1."


def collect_neighbors(prefix):
    try:
        raw = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode()
    except Exception:
        return []

    found = []
    for line in raw.strip().splitlines():
        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts:
            ip_addr = parts[0]
            if not ip_addr.startswith(prefix):
                continue
            mac = parts[parts.index("lladdr") + 1].upper()
            found.append({"ip": ip_addr, "mac": mac, "vendor": core_mac_lookup.get_vendor(mac)})
    return found


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                      {Y}LAN RECON{RESET}")
    print(f"{C}================================================================{RESET}")

    missing = core_utils.missing_commands("ping", "ip")
    if missing:
        print(f"\n [ERROR] Missing required system tools: {', '.join(missing)}")
        input("\n Enter...")
        return

    prefix = get_local_ip_prefix()
    print(f" [i] Scanning local network segment {prefix}0/24 ...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(wake_up_ip, [f"{prefix}{idx}" for idx in range(1, 255)]))

    found = collect_neighbors(prefix)

    print(f" {G}>>> DISCOVERY SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" TARGET RANGE:    {prefix}0/24")
    print(f" HOSTS FOUND:     {len(found)}")
    print(" ----------------------------------------------------------------")

    print(f"\n {'ID':<4} {'IP ADDRESS':<16} {'MAC ADDRESS':<18} {'VENDOR'}")
    print(" ---------------------------------------------------------------------------")
    for idx, item in enumerate(found, 1):
        print(f" [{idx:02}] {item['ip']:<16} {item['mac']:<18} {item['vendor'][:32]}")

    if not found:
        print(" No hosts were discovered in the neighbor table.")
        input("\n Enter...")
        return

    print("\n [A] Add discovered host to Wake-on-LAN vault")
    print(" [0] Back")
    choice = input("\n Selection: ").strip().lower()
    if choice != "a":
        return

    try:
        selected = int(input(" Device ID: ").strip()) - 1
        if 0 <= selected < len(found):
            target = found[selected]
            name = input(f" Asset label [{target['vendor'][:12]}]: ").strip() or target["vendor"][:12]
            note = input(" Note / credential hint: ").strip()
            database = db_wol.load_wol_profiles()
            database.append([name, target["mac"], target["ip"], note if note else "-"])
            db_wol.save_wol_profiles(database)
            print(f"\n {G}>>> VAULT UPDATE{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" STATUS:         SUCCESS")
            print(f" TARGET:         {name}")
            print(f" MAC:            {target['mac']}")
            print(f" ADDRESS:        {target['ip']}")
            time.sleep(1)
    except Exception:
        pass
