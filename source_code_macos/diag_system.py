#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import subprocess

import core_config
import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def ensure_commands(*command_names):
    missing = core_utils.missing_commands(*command_names)
    if missing:
        print(f" [ERROR] Missing required system tools: {', '.join(missing)}")
        input("\n Enter...")
        return False
    return True


def truncate(value, width):
    value = str(value or "").strip()
    if len(value) <= width:
        return value
    return value[: width - 3] + "..."


def render_connection_table(title, rows):
    print(f"\n {G}>>> {title}{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'PROTO':<6} {'STATE':<12} {'LOCAL':<24} {'REMOTE':<24} {'PROCESS':<24} {'PID':<6}")
    print(" " + "-" * 100)
    if not rows:
        print(" No data.")
        return

    for row in rows:
        print(
            f" {truncate(row['proto'], 6):<6} "
            f"{truncate(row['state'], 12):<12} "
            f"{truncate(row['local'], 24):<24} "
            f"{truncate(row['remote'], 24):<24} "
            f"{truncate(row['process'], 24):<24} "
            f"{truncate(row['pid'], 6):<6}"
        )


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
    cleaned = re.sub(r"\s+\((?:LISTEN|ESTABLISHED|CLOSED)\)$", "", cleaned)
    if "->" in cleaned:
        local, remote = cleaned.split("->", 1)
        return local, remote
    return cleaned, "*"


def collect_macos_connections(established_only=True):
    state = "ESTABLISHED" if established_only else "LISTEN"
    result = subprocess.run(
        ["lsof", "-nP", "-iTCP", f"-sTCP:{state}", "-F", "pcnT"],
        capture_output=True,
        text=True,
    )
    records = parse_lsof_records(result.stdout)
    rows = []
    for record in records:
        local, remote = split_endpoint(record.get("name", ""))
        rows.append(
            {
                "proto": "tcp",
                "state": record.get("state", state),
                "local": local or "*",
                "remote": remote if not established_only else remote or "*",
                "process": record.get("process", "Unknown"),
                "pid": record.get("pid", "-"),
            }
        )
    rows.sort(key=lambda item: (item["process"].lower(), item["local"], item["remote"]))
    return rows


def collect_macos_arp_rows():
    output = subprocess.run(["arp", "-an"], capture_output=True, text=True).stdout
    rows = []
    for line in output.splitlines():
        match = re.search(r"\(([^)]+)\) at ([^ ]+) on ([^ ]+)", line)
        if not match:
            continue
        ip_addr, mac_addr, interface = match.groups()
        flags = []
        if "permanent" in line:
            flags.append("PERMANENT")
        if "ethernet" in line:
            flags.append("ETHERNET")
        if mac_addr.lower() == "ff:ff:ff:ff:ff:ff":
            flags.append("BROADCAST")
        rows.append(
            {
                "ip": ip_addr,
                "mac": mac_addr,
                "interface": interface,
                "flags": ", ".join(flags) or "---",
            }
        )
    rows.sort(key=lambda item: (item["interface"], item["ip"]))
    return rows


def render_arp_table(title, rows):
    print(f"\n {G}>>> {title}{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'INTERFACE':<10} {'FLAGS':<18}")
    print(" " + "-" * 72)
    if not rows:
        print(" No data.")
        return
    for row in rows:
        print(
            f" {truncate(row['ip'], 18):<18} "
            f"{truncate(row['mac'], 20):<20} "
            f"{truncate(row['interface'], 10):<10} "
            f"{truncate(row['flags'], 18):<18}"
        )


def run_ipconfig():
    core_config.clear_screen()
    print(" [!] Collecting full network configuration (ifconfig, route, dns)...")
    if not ensure_commands("ifconfig", "networksetup"):
        return

    cmd = (
        "echo '--- INTERFEJSY ---'; ifconfig; "
        "echo '\n--- TRASY ---'; netstat -rn; "
        "echo '\n--- DNS ---'; scutil --dns"
    )
    res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
    print(res)
    core_report.save(res, "IPConfig_All_macOS")
    input("\n Enter...")


def run_netstat():
    while True:
        core_config.clear_screen()
        print(f"{C}================================================================{RESET}")
        print(f"                      {Y}SESSION AUDIT{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [1] Active TCP connections")
        print(" [2] Listening ports")
        print(" [0] Back")
        if not ensure_commands("lsof"):
            return

        c = input("\n Selection: ")
        if c == "0":
            break
        if c not in ("1", "2"):
            continue

        core_config.clear_screen()
        established_only = c == "1"
        title = "ACTIVE TCP CONNECTIONS" if established_only else "LISTENING PORTS"
        rows = collect_macos_connections(established_only=established_only)
        render_connection_table(title, rows)

        report_lines = [
            f"SESSION AUDIT ({'ACTIVE TCP CONNECTIONS' if established_only else 'LISTENING PORTS'})",
            "",
            "PROTO | STATE | LOCAL | REMOTE | PROCESS | PID",
            *[
                f"{row['proto']} | {row['state']} | {row['local']} | {row['remote']} | {row['process']} | {row['pid']}"
                for row in rows
            ],
        ]

        if input("\n [?] Save report? (y/n): ").lower() == "y":
            core_report.save("\n".join(report_lines), "Session_Audit_macOS")
        input("\n Enter...")


def run_arp():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                        {Y}ARP TABLE{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Collecting layer 2 / layer 3 neighbors...\n")
    if not ensure_commands("arp"):
        return
    rows = collect_macos_arp_rows()
    render_arp_table("ARP NEIGHBORS", rows)
    report_lines = [
        "ARP TABLE",
        "",
        "IP Address | MAC Address | Interface | Flags",
        *[f"{row['ip']} | {row['mac']} | {row['interface']} | {row['flags']}" for row in rows],
    ]
    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "ARP_Table_macOS")
    input("\n Enter...")
