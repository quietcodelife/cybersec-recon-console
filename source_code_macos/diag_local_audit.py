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


def summarize_macos_interfaces():
    if not core_utils.command_exists("ifconfig"):
        return []

    output = safe_run(["ifconfig"])
    rows = []
    current = None
    for raw_line in output.splitlines():
        if raw_line and not raw_line.startswith("\t") and ":" in raw_line:
            if current:
                rows.append(current)
            name = raw_line.split(":", 1)[0]
            current = {"name": name, "state": "DOWN", "ipv4": "---", "link": "---"}
            if "UP" in raw_line:
                current["state"] = "UP"
            continue

        if not current:
            continue

        line = raw_line.strip()
        if line.startswith("inet "):
            parts = line.split()
            if len(parts) > 1 and parts[1] != "127.0.0.1":
                current["ipv4"] = parts[1]
        elif line.startswith("status:"):
            status = line.split(":", 1)[1].strip().upper()
            current["link"] = status
            if status == "ACTIVE":
                current["state"] = "UP"

    if current:
        rows.append(current)

    filtered = []
    for row in rows:
        is_operational = row["ipv4"] != "---" or row["link"] == "ACTIVE"
        is_virtual_noise = row["name"].startswith(("utun", "anpi", "llw", "awdl", "bridge", "ap", "gif", "stf"))
        if is_operational and not is_virtual_noise:
            filtered.append(row)

    if filtered:
        return filtered

    fallback = []
    for row in rows:
        if row["name"] == "lo0":
            continue
        if row["ipv4"] != "---" or row["link"] == "ACTIVE":
            fallback.append(row)
    return fallback or rows[:6]


def parse_lsof_records(output):
    records = []
    current = {}
    for line in output.splitlines():
        if not line:
            continue
        field = line[0]
        value = line[1:]
        if field == "p":
            if current:
                records.append(current)
            current = {"pid": value, "process": "Unknown", "name": "", "state": "Unknown"}
        elif field == "c":
            current["process"] = value
        elif field == "n":
            current["name"] = value
        elif field == "T" and value.startswith("ST="):
            current["state"] = value.split("=", 1)[1]
    if current:
        records.append(current)
    return records


def split_endpoint(name):
    cleaned = (name or "").strip()
    cleaned = re.sub(r"\s+\((?:LISTEN|ESTABLISHED|CLOSED|TIME_WAIT)\)$", "", cleaned)
    if "->" in cleaned:
        local, remote = cleaned.split("->", 1)
        return local, remote
    return cleaned, "*"


def summarize_macos_sockets():
    if not core_utils.command_exists("lsof"):
        return []

    result = subprocess.run(
        ["lsof", "-nP", "-i", "-F", "pcnT"],
        capture_output=True,
        text=True,
        check=False,
    )
    rows = []
    for record in parse_lsof_records(result.stdout):
        local, remote = split_endpoint(record.get("name", ""))
        state = (record.get("state", "UNKNOWN") or "UNKNOWN").upper()
        if state not in {"ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT"}:
            continue
        if local in ("", "*") and remote == "*":
            continue
        rows.append(
            {
                "proto": "tcp",
                "state": state,
                "local": local or "*",
                "remote": remote or "*",
                "process": record.get("process", "Unknown"),
                "pid": record.get("pid", "-"),
            }
        )
    priority = {"ESTABLISHED": 0, "LISTEN": 1, "TIME_WAIT": 2, "CLOSE_WAIT": 3, "UNKNOWN": 4}
    rows.sort(key=lambda item: (priority.get(item["state"], 9), item["process"].lower(), item["local"]))
    return rows[:18]


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
    fqdn = display_fqdn(hostname)
    current_user = getpass.getuser()
    kernel = platform.release()
    os_name = f"macOS {platform.mac_ver()[0] or 'unknown'}"
    arch = platform.machine()
    is_root = os.geteuid() == 0

    service_states = [(name, get_launchctl_state(name)) for name in LAUNCHD_SERVICES]
    logged_users = safe_run(["who"]) if core_utils.command_exists("who") else "The 'who' command is unavailable."
    interface_rows = summarize_macos_interfaces()
    socket_rows = summarize_macos_sockets()

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

    print(f"\n {G}>>> INTERFACE SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'NAME':<10} {'STATE':<8} {'IPV4':<18} {'LINK':<12}")
    print(" " + "-" * 56)
    for row in interface_rows:
        effective_state = "ACTIVE" if row["ipv4"] != "---" or row["link"] == "ACTIVE" else row["state"]
        state_color = G if effective_state == "ACTIVE" else Y
        print(
            f" {truncate(row['name'], 10):<10} "
            f"{state_color}{truncate(effective_state, 8):<8}{RESET} "
            f"{truncate(row['ipv4'], 18):<18} "
            f"{truncate(row['link'], 12):<12}"
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
        "[Launchd / Security Services]",
    ]
    for service_name, state in service_states:
        report_lines.append(f"{service_name}: {state}")
    report_lines.extend([
        "",
        "[Logged Users]",
        logged_users,
        "",
        "[Interface Summary]",
        *[
            f"{row['name']} | {row['state']} | {row['ipv4']} | {row['link']}"
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
        core_report.save("\n".join(report_lines), "Local_Host_Audit_macOS")

    input("\n Enter...")
