#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time

import core_config

CACHE = {}
G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def get_vendor(mac):
    if not mac or mac == "00:00:00:00:00:00":
        return "System gateway"
    mac = mac.upper().replace("-", ":")
    if mac in CACHE:
        return CACHE[mac]

    if len(mac) > 1 and mac[1] in "26AE":
        result = "Private / random MAC"
        CACHE[mac] = result
        return result

    url = f"https://api.macvendors.com/{mac}"
    try:
        import requests
    except ImportError:
        return "Missing requests library"

    for _ in range(2):
        try:
            time.sleep(0.6)
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                vendor = response.text.strip()
                CACHE[mac] = vendor
                return vendor
            if response.status_code == 429:
                time.sleep(1)
        except Exception:
            pass
    return "Unknown / not in database"


def run():
    while True:
        core_config.clear_screen()
        print(f"{C}================================================================{RESET}")
        print(f"                    {Y}MAC VENDOR LOOKUP{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [i] Resolve a hardware vendor from a MAC address or OUI.\n")

        mac = input("\n MAC address [0=back]: ").strip()
        if mac == "0":
            break
        if len(mac) < 8:
            print("\n [ERROR] Provide a longer MAC address or OUI fragment.")
            input("\n Enter...")
            continue

        print(f"\n [i] Looking up vendor for {mac}...")
        vendor = get_vendor(mac)

        print(f"\n {G}>>> LOOKUP SUMMARY{RESET}")
        print(" ----------------------------------------------------------------")
        print(f" MAC ADDRESS:     {mac.upper()}")
        print(f" VENDOR:          {vendor}")

        input("\n Enter...")
