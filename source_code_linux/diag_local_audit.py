#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import getpass
import os
import platform
import re
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


def truncate(value, width):
    value = str(value or "").strip()
    if len(value) <= width:
        return value
    return value[: width - 3] + "..."


def display_fqdn(hostname):
    fqdn = socket.getfqdn(hostname)
    lowered = fqdn.lower()
    if lowered.endswith(".ip6.arpa") or lowered.endswith(".in-addr.arpa"):
        return hostname
    return fqdn or hostname


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


def parse_ip_brief(output):
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        row = (
            {
                "name": parts[0],
                "state": parts[1],
                "ipv4": next((item for item in parts[2:] if "." in item), "---"),
            }
        )
        is_noise = row["name"].startswith(("lo", "docker", "br-", "veth", "tun", "tap"))
        is_operational = row["ipv4"] != "---" or row["state"].upper() == "UP"
        if is_operational and not is_noise:
            rows.append(row)
    return rows


def parse_ss_line(line):
    parts = line.split(None, 5)
    if len(parts) < 5:
        return None

    process = "Unknown"
    pid = "-"
    if len(parts) > 5:
        proc_part = parts[5]
        name_match = re.search(r'"([^"]+)"', proc_part)
        pid_match = re.search(r"pid=(\d+)", proc_part)
        if name_match:
            process = name_match.group(1)
        if pid_match:
            pid = pid_match.group(1)

    return {
        "proto": parts[0],
        "state": parts[1],
        "local": parts[3],
        "remote": parts[4],
        "process": process,
        "pid": pid,
    }


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
    fqdn = display_fqdn(hostname)
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
    interface_rows = parse_ip_brief(ip_summary) if "unavailable" not in ip_summary.lower() else []
    socket_rows = []
    if listening_ports and "available" not in listening_ports.lower():
        for line in listening_ports.splitlines():
            parsed = parse_ss_line(line)
            if parsed and not (parsed["state"] == "UNCONN" and parsed["process"] == "Unknown"):
                socket_rows.append(parsed)
    priority = {"ESTAB": 0, "LISTEN": 1, "UNCONN": 2}
    socket_rows.sort(key=lambda item: (priority.get(item["state"], 9), item["process"].lower(), item["local"]))
    socket_rows = socket_rows[:18]

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

    print(f"\n {G}>>> INTERFACE SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'NAME':<10} {'STATE':<12} {'IPV4':<20}")
    print(" " + "-" * 46)
    for row in interface_rows:
        effective_state = "ACTIVE" if row["ipv4"] != "---" or row["state"].upper() == "UP" else row["state"]
        state_color = G if effective_state == "ACTIVE" else Y
        print(
            f" {truncate(row['name'], 10):<10} "
            f"{state_color}{truncate(effective_state, 12):<12}{RESET} "
            f"{truncate(row['ipv4'], 20):<20}"
        )
    if not interface_rows:
        print(" No interface data available.")

    print(f"\n {G}>>> SOCKET SNAPSHOT{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'PROTO':<6} {'STATE':<12} {'LOCAL':<24} {'REMOTE':<24} {'PROCESS':<20} {'PID':<6}")
    print(" " + "-" * 96)
    for row in socket_rows:
        print(
            f" {truncate(row['proto'], 6):<6} "
            f"{truncate(row['state'], 12):<12} "
            f"{truncate(row['local'], 24):<24} "
            f"{truncate(row['remote'], 24):<24} "
            f"{truncate(row['process'], 20):<20} "
            f"{truncate(row['pid'], 6):<6}"
        )
    if not socket_rows:
        print(" No socket data available.")

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
        "[Interface Summary]",
        *[
            f"{row['name']} | {row['state']} | {row['ipv4']}"
            for row in interface_rows
        ],
        "",
        "[Socket Snapshot]",
        *[
            f"{row['proto']} | {row['state']} | {row['local']} | {row['remote']} | {row['process']} | {row['pid']}"
            for row in socket_rows
        ],
    ])

    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "Local_Host_Audit")

    input("\n Enter...")
