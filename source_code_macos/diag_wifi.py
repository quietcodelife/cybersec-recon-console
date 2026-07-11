#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import subprocess

import core_config
import core_report
import core_utils

AIRPORT_BIN = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
C, Y, G, R, RESET = "\033[96m", "\033[93m", "\033[92m", "\033[91m", "\033[0m"


def find_wifi_device():
    if not core_utils.command_exists("networksetup"):
        return None
    try:
        output = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
    except Exception:
        return None

    current_port = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and current_port and "wi-fi" in current_port.lower():
            return line.split(":", 1)[1].strip()
    return None


def list_preferred_networks(device):
    try:
        output = subprocess.check_output(["networksetup", "-listpreferredwirelessnetworks", device], text=True)
    except Exception as exc:
        return [f"Failed to read preferred network list: {exc}"]
    return [line.strip() for line in output.splitlines()[1:] if line.strip()]


def run_airport_scan():
    if not os.path.exists(AIRPORT_BIN):
        return "Airport utility not found."
    try:
        return subprocess.check_output([AIRPORT_BIN, "-s"], text=True, stderr=subprocess.DEVNULL)
    except Exception as exc:
        return f"Airport scan failed: {exc}"


def read_wifi_password(ssid):
    if not ssid:
        return "Keychain password lookup was skipped."
    try:
        return subprocess.check_output(
            ["security", "find-generic-password", "-D", "AirPort network password", "-wa", ssid],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except subprocess.CalledProcessError as exc:
        return (exc.output or "").strip() or "Failed to read password from Keychain."
    except Exception as exc:
        return f"Keychain lookup error: {exc}"


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                {Y}WIFI SECURITY AUDITOR (macOS){RESET}")
    print(f"{C}================================================================{RESET}")

    device = find_wifi_device()
    if not device:
        print("\n [ERROR] No Wi-Fi interface was detected by networksetup.")
        input("\n Enter...")
        return

    preferred = list_preferred_networks(device)
    airport_scan = run_airport_scan()

    print(f"\n [i] Wi-Fi interface: {device}")
    print(f"\n {G}>>> PREFERRED NETWORKS{RESET}")
    print(" ----------------------------------------------------------------")
    if preferred:
        for ssid in preferred:
            print(f" - {ssid}")
    else:
        print(" No saved preferred networks.")

    print(f"\n {G}>>> AIRPORT SCAN{RESET}")
    print(" ----------------------------------------------------------------")
    print(airport_scan)

    print(f"\n {G}>>> KEYCHAIN LOOKUP{RESET}")
    print(" ----------------------------------------------------------------")
    print(" Pick an SSID from the preferred network list if you want to check")
    print(" whether a saved password is available in Keychain.")
    selected_ssid = input("\n SSID for password lookup (optional, Enter to skip): ").strip()
    keychain_result = read_wifi_password(selected_ssid)

    print(f"\n {G}>>> KEYCHAIN RESULT{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" SSID:           {selected_ssid or '-'}")
    print(f" RESULT:         {keychain_result}")

    report = "\n".join(
        [
            f"Wi-Fi device: {device}",
            "",
            "[Preferred Networks]",
            *preferred,
            "",
            "[Airport Scan]",
            airport_scan,
            "",
            "[Keychain Lookup]",
            f"SSID: {selected_ssid or '-'}",
            keychain_result,
        ]
    )
    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save(report, "WiFi_Audit_macOS")
    input("\n Enter...")
