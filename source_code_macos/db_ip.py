#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress
import os
import time

import core_config

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
DB_PATH = core_config.DB_IP


def ensure_db_file():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if not os.path.exists(DB_PATH):
        with open(DB_PATH, "w", encoding="utf-8") as file:
            file.write("")


def load_all_profiles():
    ensure_db_file()
    valid_profiles = []
    try:
        with open(DB_PATH, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                parts = [part.strip() for part in line.split(";") if part.strip() or line.count(";") >= 5]
                if len(parts) > 0 and "." in parts[0] and parts[0].count(".") == 3:
                    parts = ["-"] + parts
                while len(parts) < 6:
                    parts.append("-")
                valid_profiles.append(parts[:6])
    except Exception:
        pass
    return valid_profiles


def save_all(profiles):
    ensure_db_file()
    try:
        with open(DB_PATH, "w", encoding="utf-8") as file:
            for profile in profiles:
                file.write(";".join(profile[:6]) + ";\n")
    except Exception as exc:
        print(f" Error: {exc}")
        time.sleep(1)


def validate_optional_ipv4(value, label):
    value = (value or "").strip()
    if value in ("", "-"):
        return "-"
    try:
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        raise ValueError(f"{label}: invalid IPv4 address.")


def validate_mask(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Subnet mask cannot be empty.")
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{value}")
        return value
    except ValueError:
        raise ValueError("Invalid subnet mask.")


def normalize_profile(profile):
    normalized = list(profile[:6])
    while len(normalized) < 6:
        normalized.append("-")
    normalized[0] = normalized[0].strip() or "Profile"
    normalized[1] = validate_optional_ipv4(normalized[1], "Adres IP")
    normalized[2] = validate_mask(normalized[2])
    normalized[3] = validate_optional_ipv4(normalized[3], "Brama")
    normalized[4] = validate_optional_ipv4(normalized[4], "DNS 1")
    normalized[5] = validate_optional_ipv4(normalized[5], "DNS 2")
    return normalized


def upsert_profile(profile):
    normalized = normalize_profile(profile)
    profiles = load_all_profiles()
    replaced = False
    for index, current in enumerate(profiles):
        if current[0].strip().lower() == normalized[0].strip().lower():
            profiles[index] = normalized
            replaced = True
            break
    if not replaced:
        profiles.append(normalized)
    save_all(profiles)
    return replaced, normalized


def print_header(profiles, mode):
    fname = os.path.basename(DB_PATH)
    print(f"{C}=== PROFILE VAULT :: IP ADDRESSING ({fname}) ==={RESET}")
    print(" Stored IPv4 configurations for fast restore on selected interfaces.\n")

    header = f" {'ID':<3} | {'NAME':<16} | {'IP':<15} | {'MASK':<15} | {'GATEWAY':<15} | {'DNS 1':<15}"
    print(header)
    print("-" * len(header))

    if not profiles:
        print(f" {Y}[EMPTY VAULT]{RESET} No saved profiles.")
        print(" Add the first profile manually or save a snapshot from the selected interface panel.")
    else:
        for index, profile in enumerate(profiles, 1):
            name = (profile[0][:14] + "..") if len(profile[0]) > 16 else profile[0]
            print(
                f" {index:<3} | {name:<16} | {profile[1]:<15} | {profile[2]:<15} | "
                f"{profile[3]:<15} | {profile[4]:<15}"
            )

    print("-" * len(header))
    if mode == "SELECT":
        print(f" {G}[ID]{RESET} Select   {G}[A]{RESET} Add   {G}[E]{RESET} Edit   {G}[D]{RESET} Delete   {R}[0]{RESET} Back")
    else:
        print(f" {G}[A]{RESET} Add   {G}[E]{RESET} Edit   {G}[D]{RESET} Delete   {R}[0]{RESET} Back")


def select_profile_menu(mode="SELECT"):
    ensure_db_file()
    while True:
        profiles = load_all_profiles()
        core_config.clear_screen()
        print_header(profiles, mode)

        if not profiles:
            quick = input("\n Create the first profile now? [Y/n/Enter]: ").strip().lower()
            if quick in ("", "y", "yes"):
                new_profile = manual_input_profile()
                if new_profile:
                    profiles.append(new_profile)
                    save_all(profiles)
                continue
            if quick == "0" or quick == "n":
                return None
            continue

        choice = input("\n Selection: ").lower().strip()
        if choice == "0":
            return None
        if choice == "a":
            new_profile = manual_input_profile()
            if new_profile:
                upsert_profile(new_profile)
            continue
        if choice == "d":
            try:
                idx = int(input(" Profile ID to delete: ").strip()) - 1
                if 0 <= idx < len(profiles):
                    del profiles[idx]
                    save_all(profiles)
            except Exception:
                pass
            continue
        if choice == "e":
            try:
                idx = int(input(" Profile ID to edit: ").strip()) - 1
                if 0 <= idx < len(profiles):
                    edited = manual_input_profile(profiles[idx])
                    if edited:
                        profiles[idx] = normalize_profile(edited)
                        save_all(profiles)
            except Exception:
                pass
            continue
        if mode == "SELECT":
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(profiles):
                    return profiles[idx]
            except Exception:
                pass


def run_management():
    select_profile_menu(mode="MANAGE")


def manual_input_profile(old_data=None):
    current = old_data if old_data else ["Office-LAN", "", "255.255.255.0", "-", "1.1.1.1", "8.8.8.8"]

    while True:
        print(f"\n{Y}--- IPV4 PROFILE WIZARD ---{RESET}")
        print(" Press Enter to keep the current value, or `0` to cancel.\n")

        name = input(f" Profile name [{current[0]}]: ").strip() or current[0]
        if name == "0":
            return None

        ip_value = input(f" IP address [{current[1]}]: ").strip() or current[1]
        if ip_value == "0":
            return None
        if not ip_value or ip_value == "-":
            print(f" {R}[ERROR]{RESET} IP address is required.")
            time.sleep(1.2)
            continue

        print(f" Mask (current: {current[2]}):")
        print(" [1] 255.255.255.0 (/24)  [2] 255.255.0.0 (/16)  [3] 255.0.0.0 (/8)  [4] CUSTOM")
        mask_choice = input(" Selection: ").strip()
        if mask_choice == "1":
            mask = "255.255.255.0"
        elif mask_choice == "2":
            mask = "255.255.0.0"
        elif mask_choice == "3":
            mask = "255.0.0.0"
        elif mask_choice == "4":
            mask = input(" Enter custom mask: ").strip() or current[2]
        else:
            mask = current[2]

        gateway = input(f" Default gateway [{current[3]}]: ").strip() or current[3]
        if gateway == "0":
            return None
        dns1 = input(f" DNS 1 [{current[4]}]: ").strip() or current[4]
        if dns1 == "0":
            return None
        dns2 = input(f" DNS 2 [{current[5]}]: ").strip() or current[5]
        if dns2 == "0":
            return None

        try:
            ip_value = validate_optional_ipv4(ip_value, "Adres IP")
            mask = validate_mask(mask)
            gateway = validate_optional_ipv4(gateway, "Gateway")
            dns1 = validate_optional_ipv4(dns1, "DNS 1")
            dns2 = validate_optional_ipv4(dns2, "DNS 2")
        except ValueError as exc:
            print(f" {R}[ERROR]{RESET} {exc}")
            time.sleep(1.5)
            continue

        return [name, ip_value, mask, gateway, dns1, dns2]
