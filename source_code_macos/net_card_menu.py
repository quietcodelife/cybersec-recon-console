#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress
import subprocess
import time

import core_config
import core_utils
import db_ip

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'


def ensure_commands(*command_names):
    missing = core_utils.missing_commands(*command_names)
    if missing:
        print(f" {R}[ERROR]{RESET} Missing required system tools: {', '.join(missing)}")
        time.sleep(2)
        return False
    return True


def get_hardware_port_map():
    mapping = {}
    try:
        output = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
    except Exception:
        return mapping

    port_name = None
    device_name = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            port_name = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            device_name = line.split(":", 1)[1].strip()
        elif line.startswith("Ethernet Address:") and port_name and device_name:
            mapping[device_name] = port_name
            port_name = None
            device_name = None
    return mapping


def get_adapter_status(iface):
    try:
        output = subprocess.check_output(["ifconfig", iface], text=True, stderr=subprocess.DEVNULL)
        mac = "00:00:00:00:00:00"
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("ether "):
                mac = line.split()[1]
        status = "UP" if "status: active" in output.lower() or "status: unknown" in output.lower() else "DOWN"
        color = G if status == "UP" else R
        return f"{color}{status}{RESET}", mac
    except Exception:
        return f"{R}DOWN{RESET}", "00:00:00:00:00:00"


def get_current_config(iface):
    cfg = {"ip": "-", "mask": "-", "gw": "-", "dns1": "-", "dns2": "-", "service": "-"}
    hardware_map = get_hardware_port_map()
    service = hardware_map.get(iface, "-")
    cfg["service"] = service

    try:
        output = subprocess.check_output(["ifconfig", iface], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("inet "):
                parts = stripped.split()
                cfg["ip"] = parts[1]
                if "netmask" in parts:
                    hex_mask = parts[parts.index("netmask") + 1]
                    mask_int = int(hex_mask, 16)
                    cfg["mask"] = str(ipaddress.IPv4Address(mask_int))
                break
    except Exception:
        pass

    try:
        route_output = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
        for line in route_output.splitlines():
            if "gateway:" in line:
                cfg["gw"] = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass

    if service != "-" and core_utils.command_exists("networksetup"):
        try:
            dns_output = subprocess.check_output(["networksetup", "-getdnsservers", service], text=True, stderr=subprocess.DEVNULL)
            dns_lines = [line.strip() for line in dns_output.splitlines() if line.strip() and "aren't any" not in line.lower()]
            if dns_lines:
                cfg["dns1"] = dns_lines[0]
            if len(dns_lines) > 1:
                cfg["dns2"] = dns_lines[1]
        except Exception:
            pass
    return cfg


def mask_to_cidr(mask):
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return 24


def apply_config(iface, ip, mask, gw, d1, d2):
    cfg = get_current_config(iface)
    service = cfg["service"]
    if service == "-":
        print(f" {R}[ERROR]{RESET} No network service was found for interface {iface}.")
        time.sleep(2)
        return

    print(f" [i] Configuring network service '{service}'...")
    try:
        subprocess.run(["sudo", "networksetup", "-setmanual", service, ip, mask, gw if gw not in ("-", "", "0.0.0.0") else ip], check=False)
        dns_servers = [item for item in [d1, d2] if item not in ("", "-", None)]
        if dns_servers:
            subprocess.run(["sudo", "networksetup", "-setdnsservers", service, *dns_servers], check=False)
        else:
            subprocess.run(["sudo", "networksetup", "-setdnsservers", service, "Empty"], check=False)
        print(f" {G}[SUCCESS]{RESET} Applied IP configuration: {ip}/{mask_to_cidr(mask)}")
    except Exception as exc:
        print(f" {R}[ERROR]{RESET} {exc}")
    time.sleep(2)


def set_dhcp(iface):
    cfg = get_current_config(iface)
    service = cfg["service"]
    if service == "-":
        print(f" {R}[ERROR]{RESET} No network service was found.")
        time.sleep(2)
        return

    print(f" [i] Enabling DHCP for '{service}'...")
    try:
        subprocess.run(["sudo", "networksetup", "-setdhcp", service], check=False)
        subprocess.run(["sudo", "networksetup", "-setdnsservers", service, "Empty"], check=False)
        print(f" {G}[SUCCESS]{RESET} DHCP is now active.")
    except Exception as exc:
        print(f" {R}[ERROR]{RESET} {exc}")
    time.sleep(2)


def toggle_iface(iface, state):
    print(f" [i] Changing {iface} state to: {state.upper()}...")
    try:
        if state == "down":
            subprocess.run(["sudo", "ifconfig", iface, "down"], check=False)
        else:
            subprocess.run(["sudo", "ifconfig", iface, "up"], check=False)
    except Exception as exc:
        print(f" {R}[ERROR]{RESET} {exc}")
    time.sleep(1.5)


def run(iface):
    if not ensure_commands("ifconfig", "networksetup"):
        return

    while True:
        core_config.clear_screen()
        status, mac = get_adapter_status(iface)
        cfg = get_current_config(iface)

        print(f"{C}================================================================{RESET}")
        print(f"        INTERFACE: {Y}{iface}{RESET}  |  MAC: {mac}")
        print(f"        SERVICE: {cfg['service']}")
        print(f"        STATUS: {status:<19}")
        print(f"        IP: {cfg['ip']:<15} MASK: {cfg['mask']}")
        print(f"        GW: {cfg['gw']:<15} DNS: {cfg['dns1']}, {cfg['dns2']}")
        print(f"{C}================================================================{RESET}")

        print(f" [{G}1{RESET}] DHCP (Auto)")
        print(f" [{G}2{RESET}] Set Static IP")
        print(f" [{G}3{RESET}] Profile Vault")
        print(f" [{G}4{RESET}] Restart (Down/Up)")
        print(f" [{G}ON{RESET}] Enable Interface   [{R}OFF{RESET}] Disable Interface")
        print(f" [{G}5{RESET}] Save Snapshot")
        print(f"\n [{R}0{RESET}] Back")

        c = input("\n Selection: ").strip().lower()

        if c == "0":
            break
        elif c == "1":
            set_dhcp(iface)
        elif c == "2":
            data = db_ip.manual_input_profile()
            if data:
                apply_config(iface, data[1], data[2], data[3], data[4], data[5])
        elif c == "3":
            profile = db_ip.select_profile_menu(mode="SELECT")
            if profile:
                apply_config(iface, profile[1], profile[2], profile[3], profile[4], profile[5])
        elif c == "4":
            toggle_iface(iface, "down")
            toggle_iface(iface, "up")
        elif c == "on":
            toggle_iface(iface, "up")
        elif c == "off":
            toggle_iface(iface, "down")
        elif c == "5":
            default_name = f"{iface}-{cfg['ip']}" if cfg["ip"] not in ("", "-") else f"{iface}-snapshot"
            name = input(f" Profile name [{default_name}]: ").strip() or default_name
            try:
                replaced, saved_profile = db_ip.upsert_profile(
                    [name, cfg["ip"], cfg["mask"], cfg["gw"], cfg["dns1"], cfg["dns2"]]
                )
                action = "Updated" if replaced else "Saved"
                print(f" {G}{action}.{RESET} Profile: {saved_profile[0]}")
            except ValueError as exc:
                print(f" {R}[ERROR]{RESET} Snapshot was not saved: {exc}")
            time.sleep(1.2)
