#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import socket
import time

import core_config

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
DB_PATH = core_config.DB_WOL


def load_wol_profiles():
    if not os.path.exists(DB_PATH):
        return []
    profiles = []
    try:
        with open(DB_PATH, "r", encoding="utf-8") as file:
            for line in file:
                parts = line.strip().split(";")
                while len(parts) < 4:
                    parts.append("-")
                profiles.append([parts[0], parts[1], parts[2], parts[3]])
    except Exception:
        pass
    return profiles


def save_wol_profiles(profiles):
    try:
        with open(DB_PATH, "w", encoding="utf-8") as file:
            for profile in profiles:
                file.write(f"{profile[0]};{profile[1]};{profile[2]};{profile[3]}\n")
    except Exception:
        pass


def send_magic_packet(mac, ip_broadcast="255.255.255.255"):
    mac_clean = mac.replace(":", "").replace("-", "")
    if len(mac_clean) != 12:
        return False, "Invalid MAC address"
    try:
        data = bytes.fromhex("FF" * 6 + mac_clean * 16)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, (ip_broadcast, 9))
        sock.close()
        return True, "Magic packet sent"
    except Exception as exc:
        return False, str(exc)


def manual_input_wol(old=None):
    current = old if old else ["Workstation", "", "192.168.1.255", "-"]
    print(f"\n {Y}>>> WOL PROFILE WIZARD{RESET}")
    name = input(f" Name [{current[0]}]: ").strip() or current[0]
    mac = input(f" MAC [{current[1]}]: ").strip() or current[1]
    broadcast = input(f" Broadcast IP [{current[2]}]: ").strip() or current[2]
    note = input(f" Note / credential hint [{current[3]}]: ").strip()
    return [name, mac, broadcast, note if note else current[3]]


def run():
    while True:
        profiles = load_wol_profiles()
        core_config.clear_screen()
        print(f"{C}================================================================{RESET}")
        print(f"                   {Y}WAKE ON LAN MANAGER{RESET}")
        print(f"{C}================================================================{RESET}")
        print(f" {G}>>> VAULT SUMMARY{RESET}")
        print(" ---------------------------------------------------------------------------")
        print(f" PROFILES:       {len(profiles)}")
        print(" PURPOSE:        Wake-on-LAN launch targets and broadcast routes")
        print(" ---------------------------------------------------------------------------")
        print(f" {'ID':<3} {'NAME':<18} {'MAC':<18} {'BROADCAST':<15} {'NOTE'}")
        print(" ---------------------------------------------------------------------------")
        if profiles:
            for index, profile in enumerate(profiles, 1):
                print(f" {index:<3} {profile[0]:<18} {profile[1]:<18} {profile[2]:<15} {profile[3]}")
        else:
            print(" No saved Wake-on-LAN profiles.")
        print(" ---------------------------------------------------------------------------")
        print(" [ID] Wake target")
        print(" [A] Add profile")
        print(" [E] Edit profile")
        print(" [D] Delete profile")
        print(" [0] Back")

        choice = input("\n Selection: ").strip().lower()
        if choice == "0":
            break
        if choice == "a":
            data = manual_input_wol()
            if data:
                profiles.append(data)
                save_wol_profiles(profiles)
            continue
        if choice == "d":
            try:
                idx = int(input(" Profile ID to delete: ").strip()) - 1
                if 0 <= idx < len(profiles):
                    del profiles[idx]
                    save_wol_profiles(profiles)
            except Exception:
                pass
            continue
        if choice == "e":
            try:
                idx = int(input(" Profile ID to edit: ").strip()) - 1
                if 0 <= idx < len(profiles):
                    data = manual_input_wol(profiles[idx])
                    if data:
                        profiles[idx] = data
                        save_wol_profiles(profiles)
            except Exception:
                pass
            continue

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(profiles):
                success, message = send_magic_packet(profiles[idx][1], profiles[idx][2])
                print(f"\n {G if success else R}>>> WAKE RESULT{RESET}")
                print(" ---------------------------------------------------------------------------")
                print(f" TARGET:         {profiles[idx][0]}")
                print(f" MAC:            {profiles[idx][1]}")
                print(f" BROADCAST:      {profiles[idx][2]}")
                print(f" STATUS:         {message}")
                time.sleep(1.4)
        except Exception:
            pass
