#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import glob
import os

import core_config
import core_report

C, Y, G, R, RESET = "\033[96m", "\033[93m", "\033[92m", "\033[91m", "\033[0m"


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                {Y}WIFI SECURITY AUDITOR (Linux){RESET}")
    print(f"{C}================================================================{RESET}")

    if os.geteuid() != 0:
        print("\n [ERROR] Root privileges are required for Wi-Fi profile inspection.")
        print(" [i] Saved Wi-Fi credentials on Linux are protected by the system.")
        input("\n Enter...")
        return

    paths_to_check = [
        "/etc/NetworkManager/system-connections/",
        "/run/NetworkManager/system-connections/",
    ]

    available_paths = [path for path in paths_to_check if os.path.exists(path)]
    if not available_paths:
        print("\n [ERROR] NetworkManager profile directories were not found.")
        print(" [i] The system may be using a different wireless manager.")
        input("\n Enter...")
        return

    data = []
    for path in available_paths:
        try:
            for full_path in glob.glob(os.path.join(path, "*")):
                try:
                    with open(full_path, "r", encoding="utf-8") as file:
                        content = file.read()
                    ssid = None
                    psk = None
                    key_mgmt = "Open"
                    current_section = ""
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("[") and line.endswith("]"):
                            current_section = line
                        if current_section == "[wifi]" and line.startswith("ssid="):
                            ssid = line.split("=", 1)[1].strip()
                        if current_section == "[wifi-security]":
                            if line.startswith("psk="):
                                psk = line.split("=", 1)[1].strip()
                            if line.startswith("key-mgmt="):
                                key_mgmt = line.split("=", 1)[1].strip()
                    if ssid:
                        entry = (ssid, key_mgmt, psk if psk else "[NONE / SYSTEM]")
                        if entry not in data:
                            data.append(entry)
                except Exception:
                    pass
        except Exception:
            pass

    print(f"\n {G}>>> WIFI PROFILE SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" PROFILES FOUND: {len(data)}")
    print(" ----------------------------------------------------------------")
    if not data:
        print(" No saved Wi-Fi profiles were found.")
        print(" If this is a live environment, connect to a network and try again.")
        input("\n Enter...")
        return

    print(f" {'SSID':<30} {'TYPE':<18} {'PASSWORD / STATUS'}")
    print(" ---------------------------------------------------------------------------")
    report_lines = []
    for ssid, auth_type, password in data:
        print(f" {ssid:<30} {auth_type:<18} {password}")
        report_lines.append(f"{ssid} | {auth_type} | {password}")

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "WiFi_Passwords_Linux")
    input("\n Enter...")
