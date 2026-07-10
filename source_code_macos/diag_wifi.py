#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import subprocess

import core_config
import core_report
import core_utils


AIRPORT_BIN = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"


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
    lines = output.splitlines()[1:]
    return [line.strip() for line in lines if line.strip()]


def run_airport_scan():
    if not os.path.exists(AIRPORT_BIN):
        return "Airport utility not found."
    try:
        return subprocess.check_output([AIRPORT_BIN, "-s"], text=True, stderr=subprocess.DEVNULL)
    except Exception as exc:
        return f"Airport scan failed: {exc}"


def read_wifi_password(ssid):
    ssid = (ssid or "").strip()
    if not ssid:
        return "Keychain password lookup was skipped."
    try:
        return subprocess.check_output(
            ["security", "find-generic-password", "-D", "AirPort network password", "-wa", ssid],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except subprocess.CalledProcessError as exc:
        output = (exc.output or "").strip()
        return output or "Failed to read password from Keychain."
    except Exception as exc:
        return f"Keychain lookup error: {exc}"


def run():
    core_config.clear_screen()
    print("=" * 60)
    print("         WIFI SECURITY AUDITOR (macOS)")
    print("=" * 60)

    device = find_wifi_device()
    if not device:
        print(" [!] No Wi-Fi interface was detected by networksetup.")
        input("\n Enter...")
        return

    preferred = list_preferred_networks(device)
    airport_scan = run_airport_scan()

    print(f" [i] Wi-Fi interface: {device}\n")
    print(" PREFERRED NETWORKS:")
    print("-" * 60)
    if preferred:
        for ssid in preferred:
            print(f" - {ssid}")
    else:
        print(" No saved preferred networks.")

    print("\n AIRPORT SCAN:")
    print("-" * 60)
    print(airport_scan)

    print("\n KEYCHAIN LOOKUP:")
    print("-" * 60)
    print(" You can now enter an SSID from the preferred networks list to try")
    print(" reading the saved password from Keychain.")
    selected_ssid = input("\n [optional] Enter SSID for password lookup or press Enter to skip: ").strip()
    keychain_result = read_wifi_password(selected_ssid)

    print("\n KEYCHAIN NOTE:")
    print("-" * 60)
    if selected_ssid:
        print(f" SSID: {selected_ssid}")
        print(keychain_result)
    else:
        print(" Skip the lookup or provide a specific SSID the next time you run this module.")

    report = "\n".join([
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
    ])
    if input("\n Save report? (y/n): ").lower().strip() == "y":
        core_report.save(report, "WiFi_Audit_macOS")

    input("\n Enter...")
