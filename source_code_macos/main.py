#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import importlib
import os
import subprocess
import sys
import time

import core_config
import core_utils

OPTIONAL_MODULES = [
    "diag_ping",
    "diag_tracert",
    "diag_dns",
    "diag_wifi",
    "diag_geo_ip",
    "diag_system",
    "diag_flush",
    "diag_hosts",
    "db_ip",
    "db_wol",
    "net_card_menu",
    "diag_port_scan",
    "diag_whois",
    "diag_bandwidth",
    "core_mac_lookup",
    "diag_subnet",
    "diag_dashboard",
    "diag_ssl",
    "diag_tls_inspector",
    "diag_http_recon",
    "diag_http_fingerprint",
    "diag_security_headers",
    "diag_local_audit",
    "diag_firewall_audit",
]

MODULE_ERRORS = {}

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
APP_TITLE = "CYBERSEC RECON CONSOLE"
APP_SUBTITLE = "macOS Security Operations Toolkit"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRAME_WIDTH = 70


def load_optional_modules():
    for module_name in OPTIONAL_MODULES:
        try:
            globals()[module_name] = importlib.import_module(module_name)
        except Exception as exc:
            MODULE_ERRORS[module_name] = exc


def run_module_action(module_name, action_name):
    module = globals().get(module_name)
    if module is None:
        err = MODULE_ERRORS.get(module_name)
        print(f"\n {R}[UNAVAILABLE]{RESET} Module {module_name} could not be loaded.")
        if err is not None:
            print(f" Cause: {type(err).__name__}: {err}")
        input("\n Enter...")
        return
    getattr(module, action_name)()


def run_net_card_menu(interface_name):
    module = globals().get("net_card_menu")
    if module is None:
        err = MODULE_ERRORS.get("net_card_menu")
        print(f"\n {R}[UNAVAILABLE]{RESET} Module net_card_menu could not be loaded.")
        if err is not None:
            print(f" Cause: {type(err).__name__}: {err}")
        input("\n Enter...")
        return
    module.run(interface_name)


load_optional_modules()


def colorize_state(value):
    return f"{G}{value}{RESET}" if value in ("READY", "UP", "macOS") else f"{R}{value}{RESET}"


def truncate_text(value, width):
    value = str(value or "")
    if len(value) <= width:
        return value
    if width <= 2:
        return value[:width]
    return value[: width - 2] + ".."


def state_cell(value, width=8):
    label = truncate_text(value, width).ljust(width)
    return colorize_state(label)


def frame_line(content="", align="left", accent=None):
    if align == "center":
        rendered = content.center(FRAME_WIDTH)
    elif align == "right":
        rendered = content.rjust(FRAME_WIDTH)
    else:
        rendered = content.ljust(FRAME_WIDTH)
    if accent:
        rendered = f"{accent}{rendered}{RESET}"
    return f"{C}║{RESET}{rendered}{C}║{RESET}"


def print_header():
    print(f"{C}╔{'═' * FRAME_WIDTH}╗{RESET}")
    print(frame_line(APP_TITLE, align="center", accent=Y))
    print(frame_line(APP_SUBTITLE, align="center"))
    print(f"{C}╠{'═' * FRAME_WIDTH}╣{RESET}")
    print(frame_line("Runtime: macOS operator station"))
    print(frame_line("Mode: RECON | ENUMERATION | LOCAL AUDIT"))
    print(f"{C}╚{'═' * FRAME_WIDTH}╝{RESET}")


def print_readiness_panel(adapters):
    modules_ready = len(OPTIONAL_MODULES) - len(MODULE_ERRORS)
    modules_total = len(OPTIONAL_MODULES)
    interfaces_up = sum(1 for info in adapters.values() if info.get("status") == "UP")
    interface_total = len(adapters)
    module_state = f"{G}{modules_ready}/{modules_total}{RESET}"
    iface_state = f"{G}{interfaces_up}{RESET}/{interface_total}" if interface_total else f"{R}0/0{RESET}"
    print(f"\n {C}[ RUNTIME ]{RESET} Platform: {colorize_state('macOS')}   Modules: {module_state}   Interfaces Up: {iface_state}")
    if MODULE_ERRORS:
        print(f" {Y}[ INFO ]{RESET} Some modules did not load correctly. The console will show the cause when you try to use them.")


def print_interface_table(adapters):
    iface_names = sorted(adapters.keys())
    print(f"\n {C}[ INTERFACES ]{RESET} Select a number to open the interface control panel.")
    print(f" {Y}{'ID':<4} {'INTERFACE':<16} {'STATE':<8} {'IP':<18} {'LINK'}{RESET}")
    print(f" {C}-----------------------------------------------------------------------{RESET}")

    if not iface_names:
        print(f" {R}--{RESET}  No network interfaces detected.")
        return iface_names

    for index, name in enumerate(iface_names, 1):
        info = adapters[name]
        state = state_cell(info["status"], 8)
        iface_label = truncate_text(name, 16)
        ip_addr = truncate_text(info.get("ip", "---"), 18)
        speed = truncate_text(info.get("speed", "--"), 16)
        print(
            f" [{G}{index:02}{RESET}] "
            f"{iface_label:<16} "
            f"{state} "
            f"{ip_addr:<18} "
            f"{speed}"
        )
    return iface_names


def print_menu_block(title, entries):
    print(f"\n {C}[ {title} ]{RESET}")
    for key, label in entries:
        print(f" [{G}{key:<2}{RESET}] {label}")


def check_runtime_requirements():
    missing_python = core_utils.missing_python_modules(*core_utils.REQUIRED_PYTHON_MODULES)
    missing_system = core_utils.missing_commands(*core_utils.REQUIRED_SYSTEM_COMMANDS)

    if core_utils.is_macos_platform() and not missing_python and not missing_system:
        return

    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                 {Y}RUNTIME REQUIREMENTS CHECK{RESET}")
    print(f"{C}================================================================{RESET}")

    if not core_utils.is_macos_platform():
        print(f"\n {R}[ERROR]{RESET} The `source_code_macos` variant requires macOS.")

    if missing_python:
        print(f"\n {R}[MISSING PYTHON]{RESET} Modules: {', '.join(missing_python)}")
        print(f" Install with: bash {os.path.join(PROJECT_ROOT, 'setup_python_env.sh')}")

    if missing_system:
        print(f"\n {R}[MISSING SYSTEM]{RESET} Tools: {', '.join(missing_system)}")
        print(f" Install packages from: {os.path.join(PROJECT_ROOT, 'requirements-macos-brew.txt')}")
        print(f" Or run: bash {os.path.join(PROJECT_ROOT, 'bootstrap_macos.sh')}")

    sys.exit(1)


def check_first_run():
    flag_file = core_config.FIRST_RUN_FLAG
    if os.path.exists(flag_file):
        return

    core_config.clear_screen()
    print(f"\n {C}================================================================{RESET}")
    print(f"                  {Y}{APP_TITLE}{RESET}")
    print(f"               {C}{APP_SUBTITLE}{RESET}")
    print(f" {C}================================================================{RESET}")
    print(" The console will prepare the local data store, reports directory, and operational profiles.")

    confirm = input(f"\n Confirm console initialization (type {G}'YES'{RESET}): ").strip().upper()
    if confirm != "YES":
        print(f"\n {R}The program will now exit.{RESET}")
        time.sleep(2)
        sys.exit()

    core_config.init()
    with open(flag_file, "w", encoding="utf-8") as file:
        file.write("OK")
    print(f"\n {G}Environment initialization completed.{RESET}")
    time.sleep(1.5)


def show_hardware():
    core_config.clear_screen()
    print(f"{C}=== HARDWARE INVENTORY (system_profiler) ==={RESET}\n")
    if not core_utils.command_exists("system_profiler"):
        print(f" {R}[ERROR]{RESET} Missing required command: 'system_profiler'.")
        input("\n Enter...")
        return
    subprocess.run(["system_profiler", "SPNetworkDataType"])
    input("\n Enter...")


def open_network_settings():
    print(" [i] Opening macOS network settings...")
    try:
        subprocess.Popen(["open", "/System/Library/PreferencePanes/Network.prefPane"])
    except Exception as exc:
        print(f" {R}[ERROR]{RESET} {exc}")
        time.sleep(3)


def build_actions():
    return {
        "a": lambda: run_module_action("diag_system", "run_arp"),
        "b": lambda: run_module_action("diag_bandwidth", "run"),
        "c": lambda: run_module_action("diag_subnet", "run"),
        "d": lambda: run_module_action("diag_dns", "run"),
        "e": lambda: run_module_action("diag_dashboard", "run"),
        "f": lambda: run_module_action("diag_flush", "run"),
        "fw": lambda: run_module_action("diag_firewall_audit", "run"),
        "g": lambda: run_module_action("diag_geo_ip", "run"),
        "h": lambda: run_module_action("diag_hosts", "run"),
        "i": lambda: run_module_action("diag_system", "run_ipconfig"),
        "j": lambda: run_module_action("db_ip", "run_management"),
        "k": lambda: run_module_action("db_wol", "run"),
        "l": show_hardware,
        "la": lambda: run_module_action("diag_local_audit", "run"),
        "m": lambda: run_module_action("core_mac_lookup", "run"),
        "n": lambda: run_module_action("diag_system", "run_netstat"),
        "p": lambda: run_module_action("diag_port_scan", "run"),
        "r": lambda: run_module_action("diag_tracert", "run"),
        "t": lambda: run_module_action("diag_ping", "run_menu"),
        "ti": lambda: run_module_action("diag_tls_inspector", "run"),
        "ht": lambda: run_module_action("diag_http_fingerprint", "run"),
        "sh": lambda: run_module_action("diag_security_headers", "run"),
        "u": open_network_settings,
        "v": lambda: run_module_action("diag_http_recon", "run"),
        "w": lambda: run_module_action("diag_wifi", "run"),
        "x": lambda: run_module_action("diag_whois", "run"),
        "y": lambda: run_module_action("diag_ssl", "run"),
    }


def main():
    check_runtime_requirements()
    check_first_run()
    core_config.init()

    actions = build_actions()

    while True:
        try:
            core_config.clear_screen()
            adapters = core_config.get_adapters_info()
            iface_names = sorted(adapters.keys())

            print_header()
            print_readiness_panel(adapters)
            print_interface_table(adapters)

            print_menu_block("RECON", [
                ("A", "ARP Table - layer 2 and layer 3 neighbors"),
                ("D", "DNS Recon - name resolution and propagation checks"),
                ("M", "MAC Intelligence - vendor lookup from hardware address"),
                ("P", "Port Recon - service exposure on a target host"),
                ("R", "Traceroute - packet path discovery"),
                ("X", "Domain WHOIS - registration and status records"),
            ])

            print_menu_block("WEB SECURITY", [
                ("V", "HTTP Surface Recon - headers and web exposure review"),
                ("HT", "HTTP Tech Fingerprint - stack and platform detection"),
                ("SH", "Security Headers Audit - score and hardening guidance"),
                ("TI", "TLS / Certificate Inspector - trust and SAN review"),
                ("Y", "TLS Deep Audit - certificate and handshake profile"),
            ])

            print_menu_block("TELEMETRY", [
                ("B", "Bandwidth Telemetry - live interface throughput"),
                ("E", "Operations Dashboard - real-time host view"),
                ("G", "GeoIP Footprint - public IP geolocation"),
                ("T", "ICMP Probe - reachability and latency testing"),
            ])

            print_menu_block("OPERATIONS", [
                ("C", "Subnet Calculator - IPv4 network breakdown"),
                ("F", "DNS Flush - clear resolver cache"),
                ("FW", "Firewall Audit - pf policy and filter review"),
                ("H", "Hosts Override - inspect and edit hosts file"),
                ("I", "Interface Census - full local network configuration"),
                ("J", "Profile Vault - saved IPv4 configuration profiles"),
                ("K", "Wake Operations - Wake-on-LAN profile vault"),
                ("L", "Hardware Inventory - network hardware overview"),
                ("LA", "Local Host Audit - workstation security posture"),
                ("N", "Session Audit - active sockets and connections"),
                ("U", "Connection Settings - open macOS network settings"),
                ("W", "WiFi Audit - preferred networks and local scan"),
            ])

            print(f"\n [{R}0{RESET}] EXIT CONSOLE")
            choice = input("\n Selection: ").lower().strip()
            if choice == "0":
                sys.exit()

            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(iface_names):
                    run_net_card_menu(iface_names[idx])
                continue

            action = actions.get(choice)
            if action is not None:
                action()
        except KeyboardInterrupt:
            sys.exit()
        except Exception as exc:
            print(f"Error: {exc}")
            input("Enter...")


if __name__ == "__main__":
    main()
