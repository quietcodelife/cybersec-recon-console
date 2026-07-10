#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import getpass
import os
import platform
import socket
import subprocess

import core_config
import core_report
import core_utils

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

SECURITY_SERVICES = [
    "ssh",
    "sshd",
    "ufw",
    "fail2ban",
    "auditd",
    "clamav-daemon",
    "crowdstrike-falcon-sensor",
]


def safe_run(command):
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        return completed.stdout.strip() or completed.stderr.strip() or "No data"
    except Exception as exc:
        return f"Error: {exc}"


def read_os_release():
    path = "/etc/os-release"
    if not os.path.exists(path):
        return "Unknown system"
    try:
        data = {}
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
        return data.get("PRETTY_NAME", "Unknown system")
    except Exception:
        return "Unknown system"


def get_listening_ports():
    if core_utils.command_exists("ss"):
        return safe_run(["ss", "-tulpn"])
    if core_utils.command_exists("netstat"):
        return safe_run(["netstat", "-tulpn"])
    return "Neither ss nor netstat is available."


def get_users():
    return safe_run(["who"]) if core_utils.command_exists("who") else "The 'who' command is unavailable."


def get_systemctl_service_state(service_name):
    if not core_utils.command_exists("systemctl"):
        return "systemctl unavailable"
    completed = subprocess.run(
        ["systemctl", "is-active", service_name],
        capture_output=True,
        text=True,
        check=False,
    )
    state = (completed.stdout or completed.stderr).strip()
    return state or "unknown"


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                     {Y}LOCAL HOST AUDIT{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Collecting local host data...\n")

    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    current_user = getpass.getuser()
    os_name = read_os_release()
    kernel = platform.release()
    arch = platform.machine()
    is_root = os.geteuid() == 0

    security_states = []
    for service_name in SECURITY_SERVICES:
        security_states.append((service_name, get_systemctl_service_state(service_name)))

    logged_users = get_users()
    listening_ports = get_listening_ports()
    ip_summary = safe_run(["ip", "-brief", "address"]) if core_utils.command_exists("ip") else "The 'ip' command is unavailable."

    print(f" HOSTNAME:        {C}{hostname}{RESET}")
    print(f" FQDN:            {C}{fqdn}{RESET}")
    print(f" CURRENT USER:    {Y}{current_user}{RESET}")
    print(f" RUNTIME:         {Y}{'ROOT' if is_root else 'USER'}{RESET}")
    print(f" OS:              {os_name}")
    print(f" KERNEL:          {kernel}")
    print(f" ARCH:            {arch}")

    print(f"\n {Y}SECURITY SERVICES:{RESET}")
    for service_name, state in security_states:
        color = G if state == "active" else Y if state in ("inactive", "unknown", "systemctl unavailable") else R
        print(f"  {service_name:<24} {color}{state}{RESET}")

    print(f"\n {Y}LOGGED USERS:{RESET}")
    print(logged_users if logged_users else "No active sessions.")

    print(f"\n {Y}INTERFACES:{RESET}")
    print(ip_summary)

    print(f"\n {Y}LISTENING PORTS:{RESET}")
    lines = listening_ports.splitlines()
    if lines:
        for line in lines[:25]:
            print(line)
        if len(lines) > 25:
            print(f"... plus {len(lines) - 25} more lines")
    else:
        print("No data.")

    report_lines = [
        f"LOCAL HOST AUDIT :: {hostname}",
        f"FQDN: {fqdn}",
        f"User: {current_user}",
        f"Runtime: {'ROOT' if is_root else 'USER'}",
        f"OS: {os_name}",
        f"Kernel: {kernel}",
        f"Arch: {arch}",
        "",
        "[Security Services]",
    ]
    for service_name, state in security_states:
        report_lines.append(f"{service_name}: {state}")
    report_lines.extend([
        "",
        "[Logged Users]",
        logged_users,
        "",
        "[Interfaces]",
        ip_summary,
        "",
        "[Listening Ports]",
        listening_ports,
    ])

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "Local_Host_Audit")

    input("\n Enter...")
