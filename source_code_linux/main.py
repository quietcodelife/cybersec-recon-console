#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import importlib
import os
import re
import shutil
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
    "diag_net_scan",
    "diag_port_scan",
    "diag_whois",
    "diag_bandwidth",
    "diag_banner_grab",
    "diag_asn_recon",
    "core_mac_lookup",
    "diag_ct_recon",
    "diag_subnet",
    "diag_repair",
    "diag_wifi_monitor",
    "diag_dns_bench",
    "diag_dashboard",
    "diag_ssl",
    "diag_tls_inspector",
    "diag_http_recon",
    "diag_http_capture",
    "diag_http_fingerprint",
    "diag_robots_recon",
    "diag_email_security",
    "diag_directory_exposure",
    "diag_cookie_security",
    "diag_security_headers",
    "diag_subdomain_recon",
    "diag_local_audit",
    "diag_firewall_audit",
]

MODULE_ERRORS = {}

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
APP_TITLE = "CYBERSEC RECON CONSOLE"
APP_SUBTITLE = "Linux Security Operations Toolkit"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIN_LAYOUT_WIDTH = 80
MAX_LAYOUT_WIDTH = 160
MENU_GAP = 4
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


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
    normalized = str(value).strip()
    return f"{G}{value}{RESET}" if normalized in ("READY", "UP", "ROOT") else f"{R}{value}{RESET}"


def truncate_text(value, width):
    value = str(value or "")
    if len(value) <= width:
        return value
    if width <= 2:
        return value[:width]
    return value[: width - 2] + ".."


def visible_length(value):
    return len(ANSI_PATTERN.sub("", str(value)))


def pad_ansi(value, width):
    visible = visible_length(value)
    if visible >= width:
        return value
    return value + (" " * (width - visible))


def render_inventory_table(title, headers, rows):
    print(f"\n {G}>>> {title}{RESET}")
    print(" ----------------------------------------------------------------")
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    widths = [min(width, 28) for width in widths]
    header_line = " " + " ".join(f"{headers[index]:<{widths[index]}}" for index in range(len(headers)))
    print(header_line)
    print(" " + "-" * min(sum(widths) + len(widths) - 1, 96))
    if not rows:
        print(" No data.")
        return
    for row in rows:
        print(" " + " ".join(f"{truncate_text(value, widths[index]):<{widths[index]}}" for index, value in enumerate(row)))


def parse_linux_inventory_lines(output, source_label):
    rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        rows.append((source_label, stripped))
    return rows


def state_cell(value, width=8):
    label = truncate_text(value, width).ljust(width)
    return colorize_state(label)


def frame_line(content="", align="left", accent=None):
    frame_width = get_frame_width()
    if align == "center":
        rendered = content.center(frame_width)
    elif align == "right":
        rendered = content.rjust(frame_width)
    else:
        rendered = content.ljust(frame_width)
    if accent:
        rendered = f"{accent}{rendered}{RESET}"
    return f"{C}║{RESET}{rendered}{C}║{RESET}"


def get_terminal_width():
    return shutil.get_terminal_size((120, 40)).columns


def get_layout_width():
    return max(MIN_LAYOUT_WIDTH, min(MAX_LAYOUT_WIDTH, get_terminal_width()))


def get_frame_width():
    return get_layout_width() - 2


def print_header(is_root):
    frame_width = get_frame_width()
    print(f"{C}╔{'═' * frame_width}╗{RESET}")
    print(frame_line(APP_TITLE, align="center", accent=Y))
    print(frame_line(APP_SUBTITLE, align="center"))
    print(f"{C}╠{'═' * frame_width}╣{RESET}")
    runtime = "LINUX / ROOT" if is_root else "LINUX / USER"
    print(frame_line(f"Runtime: {runtime}"))
    print(frame_line("Mode: RECON | ENUMERATION | LOCAL AUDIT"))
    print(f"{C}╚{'═' * frame_width}╝{RESET}")


def print_readiness_panel(is_root, adapters):
    modules_ready = len(OPTIONAL_MODULES) - len(MODULE_ERRORS)
    modules_total = len(OPTIONAL_MODULES)
    interfaces_up = sum(1 for info in adapters.values() if info.get("status") == "UP")
    interface_total = len(adapters)
    privilege = colorize_state("ROOT") if is_root else f"{Y}LIMITED{RESET}"
    module_state = f"{G}{modules_ready}/{modules_total}{RESET}"
    iface_state = f"{G}{interfaces_up}{RESET}/{interface_total}" if interface_total else f"{R}0/0{RESET}"
    print(f"\n {C}[ RUNTIME ]{RESET} Privilege: {privilege}   Modules: {module_state}   Interfaces Up: {iface_state}")
    if MODULE_ERRORS:
        print(f" {Y}[ INFO ]{RESET} Some modules did not load correctly. The console will show the cause when you try to use them.")
    if not is_root:
        print(f" {Y}[ INFO ]{RESET} System-changing actions may require elevated privileges.")


def print_interface_table(adapters):
    iface_names = sorted(adapters.keys())
    up_entries = [
        (index, name, adapters[name])
        for index, name in enumerate(iface_names, 1)
        if adapters[name].get("status") == "UP"
    ]
    hidden_count = len(iface_names) - len(up_entries)

    print(
        f"\n {C}[ INTERFACES ]{RESET} "
        f"Showing {G}{len(up_entries)}{RESET}/{G}{len(up_entries)}{RESET} active links. "
        f"Select a visible number to open interface control."
    )
    print(f" {Y}{'ID':<4} {'INTERFACE':<16} {'STATE':<8} {'IP':<18} {'SPEED'}{RESET}")
    print(f" {C}-----------------------------------------------------------------------{RESET}")

    if not iface_names:
        print(f" {R}--{RESET}  No network interfaces detected.")
        return iface_names

    if not up_entries:
        print(f" {R}--{RESET}  No active interfaces. Open {G}I{RESET} Interface Census for full interface details.")
        return iface_names

    for index, name, info in up_entries:
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

    if hidden_count > 0:
        print(f" {Y}[ INFO ]{RESET} {hidden_count} inactive interfaces hidden. Open {G}I{RESET} Interface Census for full details.")
    return iface_names


def print_menu_block(title, entries):
    print(f"\n {C}[ {title} ]{RESET}")
    for key, label in entries:
        print(f" [{G}{key:<2}{RESET}] {label}")


def format_menu_block_lines(title, entries, width):
    inner_width = max(24, width - 2)
    lines = [pad_ansi(f"{C}[ {title} ]{RESET}", inner_width)]
    for key, label in entries:
        prefix = f" [{G}{key:<2}{RESET}] "
        available = max(8, inner_width - visible_length(prefix))
        line = f"{prefix}{truncate_text(label, available)}"
        lines.append(pad_ansi(line, inner_width))
    return lines


def print_menu_columns(blocks):
    column_width = max(40, (get_layout_width() - MENU_GAP) // 2)

    grouped = [blocks[index:index + 2] for index in range(0, len(blocks), 2)]
    for pair in grouped:
        rendered = [format_menu_block_lines(title, entries, column_width) for title, entries in pair]
        if len(rendered) == 1:
            rendered.append(["".ljust(column_width - 2)])

        row_height = max(len(rendered[0]), len(rendered[1]))
        for block_lines in rendered:
            while len(block_lines) < row_height:
                block_lines.append(" " * (column_width - 2))

        print("")
        for left_line, right_line in zip(rendered[0], rendered[1]):
            print(f" {pad_ansi(left_line, column_width - 2)}{' ' * MENU_GAP}{pad_ansi(right_line, column_width - 2)}")


def check_runtime_requirements():
    missing_python = core_utils.missing_python_modules(*core_utils.REQUIRED_PYTHON_MODULES)
    missing_system = core_utils.missing_commands(*core_utils.REQUIRED_SYSTEM_COMMANDS)
    if not core_utils.command_exists_any("tracepath", "traceroute"):
        missing_system.append("tracepath/traceroute")

    if core_utils.is_linux_platform() and not missing_python and not missing_system:
        return

    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                 {Y}RUNTIME REQUIREMENTS CHECK{RESET}")
    print(f"{C}================================================================{RESET}")

    if not core_utils.is_linux_platform():
        print(f"\n {R}[ERROR]{RESET} The `source_code_linux` variant requires Linux.")
        print(" You are launching the Linux build on a non-Linux platform.")

    if missing_python:
        print(f"\n {R}[MISSING PYTHON]{RESET} Modules: {', '.join(missing_python)}")
        print(f" Install with: python3 -m pip install -r {os.path.join(PROJECT_ROOT, 'requirements.txt')}")
        print(f" Or run: bash {os.path.join(PROJECT_ROOT, 'setup_python_env.sh')}")

    if missing_system:
        print(f"\n {R}[MISSING SYSTEM]{RESET} Tools: {', '.join(missing_system)}")
        print(" Install system packages listed in:")
        print(f" {os.path.join(PROJECT_ROOT, 'requirements-linux-apt.txt')}")

    print(f"\n {Y}RECOMMENDED SCRIPTS:{RESET}")
    print(f" Python only: bash {os.path.join(PROJECT_ROOT, 'setup_python_env.sh')}")
    print(f" Full Linux bootstrap: bash {os.path.join(PROJECT_ROOT, 'bootstrap_linux.sh')}")
    print("\n Restart the program after preparing the environment.")
    sys.exit(1)


def check_first_run():
    flag_file = core_config.FIRST_RUN_FLAG
    if os.path.exists(flag_file):
        return

    core_config.clear_screen()
    print(f"\n {C}================================================================{RESET}")
    print(f"                  {Y}{APP_TITLE}{RESET}")
    print(f"             {C}{APP_SUBTITLE}{RESET}")
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
    print(f"{C}================================================================{RESET}")
    print(f"                   {Y}HARDWARE INVENTORY{RESET}")
    print(f"{C}================================================================{RESET}")
    missing = core_utils.missing_commands("lspci", "lsusb")
    if missing:
        print(f" {R}[ERROR]{RESET} Missing required system tools: {', '.join(missing)}")
        input("\n Enter...")
        return

    print(" [i] Collecting network hardware profile...\n")
    pci_output = subprocess.run(["/bin/sh", "-c", "lspci | grep -i net"], capture_output=True, text=True).stdout
    usb_output = subprocess.run(["/bin/sh", "-c", "lsusb | grep -i -E 'net|wifi|wlan|ethernet'"], capture_output=True, text=True).stdout
    rows = parse_linux_inventory_lines(pci_output, "PCI") + parse_linux_inventory_lines(usb_output, "USB")

    print(f" {G}>>> HARDWARE SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" DETECTED ITEMS: {len(rows)}")
    print(f" PCI MATCHES:    {len(parse_linux_inventory_lines(pci_output, 'PCI'))}")
    print(f" USB MATCHES:    {len(parse_linux_inventory_lines(usb_output, 'USB'))}")
    print(" ----------------------------------------------------------------")

    render_inventory_table("NETWORK HARDWARE", ["SOURCE", "DETAIL"], rows)
    input("\n Enter...")


def open_network_settings():
    print(" [i] Opening connection editor (nm-connection-editor)...")
    if not core_utils.command_exists("nm-connection-editor"):
        print(f" {R}[ERROR]{RESET} 'nm-connection-editor' was not found.")
        time.sleep(3)
        return
    try:
        subprocess.Popen(["nm-connection-editor"], start_new_session=True)
    except FileNotFoundError:
        print(f" {R}[ERROR]{RESET} 'nm-connection-editor' was not found.")
        time.sleep(3)


def build_actions():
    return {
        "a": lambda: run_module_action("diag_system", "run_arp"),
        "b": lambda: run_module_action("diag_bandwidth", "run"),
        "as": lambda: run_module_action("diag_asn_recon", "run"),
        "bg": lambda: run_module_action("diag_banner_grab", "run"),
        "c": lambda: run_module_action("diag_subnet", "run"),
        "ct": lambda: run_module_action("diag_ct_recon", "run"),
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
        "o": lambda: run_module_action("diag_wifi_monitor", "run"),
        "p": lambda: run_module_action("diag_port_scan", "run"),
        "q": lambda: run_module_action("diag_dns_bench", "run"),
        "r": lambda: run_module_action("diag_tracert", "run"),
        "s": lambda: run_module_action("diag_net_scan", "run"),
        "sd": lambda: run_module_action("diag_subdomain_recon", "run"),
        "t": lambda: run_module_action("diag_ping", "run_menu"),
        "ti": lambda: run_module_action("diag_tls_inspector", "run"),
        "ht": lambda: run_module_action("diag_http_fingerprint", "run"),
        "hc": lambda: run_module_action("diag_http_capture", "run"),
        "ea": lambda: run_module_action("diag_email_security", "run"),
        "de": lambda: run_module_action("diag_directory_exposure", "run"),
        "cs": lambda: run_module_action("diag_cookie_security", "run"),
        "sh": lambda: run_module_action("diag_security_headers", "run"),
        "rs": lambda: run_module_action("diag_robots_recon", "run"),
        "u": open_network_settings,
        "v": lambda: run_module_action("diag_http_recon", "run"),
        "w": lambda: run_module_action("diag_wifi", "run"),
        "x": lambda: run_module_action("diag_whois", "run"),
        "y": lambda: run_module_action("diag_ssl", "run"),
        "z": lambda: run_module_action("diag_repair", "run"),
    }


def main():
    check_runtime_requirements()
    check_first_run()
    core_config.init()

    is_root = os.geteuid() == 0
    core_config.clear_screen()
    print_header(is_root)
    print(" Loading operational modules...")
    time.sleep(0.5)

    actions = build_actions()

    while True:
        try:
            core_config.clear_screen()
            adapters = core_config.get_adapters_info()
            iface_names = sorted(adapters.keys())

            print_header(is_root)
            print_readiness_panel(is_root, adapters)
            print_interface_table(adapters)

            recon_entries = [
                ("A", "ARP Intelligence - physical and local neighbor mapping"),
                ("AS", "ASN / BGP Recon - routing ownership and provider profile"),
                ("BG", "Banner Grabber - lightweight service response collection"),
                ("CT", "CT Recon - certificate transparency hostname discovery"),
                ("D", "DNS Recon - resolution and propagation checks"),
                ("M", "MAC Intelligence - vendor lookup from MAC address"),
                ("P", "Port Recon - service exposure on a target host"),
                ("R", "Route Trace - packet path discovery"),
                ("S", "LAN Recon - local network host enumeration"),
                ("SD", "Subdomain Recon - passive host discovery for a domain"),
                ("X", "Domain WHOIS - registration and status records"),
            ]

            web_entries = [
                ("CS", "Cookie Security Audit - flags, scope and persistence review"),
                ("DE", "Directory Exposure Recon - common files and panel discovery"),
                ("EA", "Email Security Audit - SPF, DMARC, MX and DKIM review"),
                ("HC", "HTTP Capture - title grab and optional page screenshot"),
                ("V", "HTTP Surface Recon - headers and web exposure review"),
                ("HT", "HTTP Tech Fingerprint - stack and platform detection"),
                ("RS", "Robots / Sitemap Recon - crawler directives and index discovery"),
                ("SH", "Security Headers Audit - score and hardening guidance"),
                ("TI", "TLS / Certificate Inspector - trust and SAN review"),
                ("Y", "TLS Deep Audit - certificate and handshake profile"),
            ]

            telemetry_entries = [
                ("B", "Bandwidth Telemetry - live interface throughput"),
                ("E", "Operations Dashboard - real-time host view"),
                ("G", "GeoIP Footprint - public IP geolocation"),
                ("O", "WiFi Telemetry - signal and quality monitor"),
                ("Q", "DNS Benchmark - compare resolver performance"),
                ("T", "ICMP Probe - reachability and latency testing"),
            ]

            operations_entries = [
                ("C", "Subnet Calculator - IPv4 network breakdown"),
                ("F", "DNS Flush - clear local resolver cache"),
                ("FW", "Firewall Audit - review active filtering rules"),
                ("H", "Hosts Override - inspect and edit hosts file"),
                ("I", "Interface Census - full local network configuration"),
                ("J", "Profile Vault - saved IPv4 configuration profiles"),
                ("K", "Wake Operations - Wake-on-LAN profile vault"),
                ("L", "Hardware Inventory - network hardware overview"),
                ("LA", "Local Host Audit - workstation security posture"),
                ("N", "Session Audit - active sockets and connections"),
                ("U", "Connection Editor - launch NetworkManager editor"),
                ("W", "WiFi Secrets Audit - saved wireless profiles"),
                ("Z", "Network Repair - reset and repair network stack"),
            ]

            print_menu_columns([
                ("RECON", recon_entries),
                ("TELEMETRY", telemetry_entries),
                ("WEB SECURITY", web_entries),
                ("OPERATIONS", operations_entries),
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
