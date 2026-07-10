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

LAUNCHD_SERVICES = [
    "com.openssh.sshd",
    "com.apple.alf.agent",
]


def safe_run(command):
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        return completed.stdout.strip() or completed.stderr.strip() or "No data"
    except Exception as exc:
        return f"Error: {exc}"


def get_launchctl_state(service_name):
    if not core_utils.command_exists("launchctl"):
        return "launchctl unavailable"
    completed = subprocess.run(
        ["launchctl", "print", f"system/{service_name}"],
        capture_output=True,
        text=True,
        check=False,
    )
    text = (completed.stdout or completed.stderr).lower()
    if "could not find service" in text:
        return "not-found"
    if "state = running" in text:
        return "running"
    if completed.returncode == 0:
        return "loaded"
    return "unknown"


def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                     {Y}LOCAL HOST AUDIT{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Collecting local host data...\n")

    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    current_user = getpass.getuser()
    kernel = platform.release()
    os_name = f"macOS {platform.mac_ver()[0] or 'unknown'}"
    arch = platform.machine()
    is_root = os.geteuid() == 0

    service_states = [(name, get_launchctl_state(name)) for name in LAUNCHD_SERVICES]
    logged_users = safe_run(["who"]) if core_utils.command_exists("who") else "The 'who' command is unavailable."
    interfaces = safe_run(["ifconfig"]) if core_utils.command_exists("ifconfig") else "The 'ifconfig' command is unavailable."
    listening_ports = safe_run(["netstat", "-anv"]) if core_utils.command_exists("netstat") else "The 'netstat' command is unavailable."

    print(f" HOSTNAME:        {C}{hostname}{RESET}")
    print(f" FQDN:            {C}{fqdn}{RESET}")
    print(f" CURRENT USER:    {Y}{current_user}{RESET}")
    print(f" RUNTIME:         {Y}{'ROOT' if is_root else 'USER'}{RESET}")
    print(f" OS:              {os_name}")
    print(f" KERNEL:          {kernel}")
    print(f" ARCH:            {arch}")

    print(f"\n {Y}LAUNCHD / SECURITY SERVICES:{RESET}")
    for service_name, state in service_states:
        color = G if state in ("running", "loaded") else Y if state in ("not-found", "launchctl unavailable") else R
        print(f"  {service_name:<28} {color}{state}{RESET}")

    print(f"\n {Y}LOGGED USERS:{RESET}")
    print(logged_users)

    print(f"\n {Y}INTERFACES:{RESET}")
    iface_lines = interfaces.splitlines()
    for line in iface_lines[:40]:
        print(line)
    if len(iface_lines) > 40:
        print(f"... plus {len(iface_lines) - 40} more lines")

    print(f"\n {Y}LISTENING / SOCKETS SNAPSHOT:{RESET}")
    socket_lines = listening_ports.splitlines()
    for line in socket_lines[:30]:
        print(line)
    if len(socket_lines) > 30:
        print(f"... plus {len(socket_lines) - 30} more lines")

    report_lines = [
        f"LOCAL HOST AUDIT :: {hostname}",
        f"FQDN: {fqdn}",
        f"User: {current_user}",
        f"Runtime: {'ROOT' if is_root else 'USER'}",
        f"OS: {os_name}",
        f"Kernel: {kernel}",
        f"Arch: {arch}",
        "",
        "[Launchd / Security Services]",
    ]
    for service_name, state in service_states:
        report_lines.append(f"{service_name}: {state}")
    report_lines.extend([
        "",
        "[Logged Users]",
        logged_users,
        "",
        "[Interfaces]",
        interfaces,
        "",
        "[Netstat]",
        listening_ports,
    ])

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "Local_Host_Audit_macOS")

    input("\n Enter...")
