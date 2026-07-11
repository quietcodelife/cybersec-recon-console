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


def parse_ss_line(line):
    parts = line.split(None, 5)
    if len(parts) < 5:
        return None

    proto = parts[0]
    state = parts[1]
    local = parts[3]
    remote = parts[4]
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
        "proto": proto,
        "state": state,
        "local": local,
        "remote": remote,
        "process": process,
        "pid": pid,
    }


def collect_linux_connections(established_only=True):
    cmd = ["ss", "-tunpH", "state", "established"] if established_only else ["ss", "-tulnpH"]
    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = []
    for line in output.splitlines():
        parsed = parse_ss_line(line)
        if parsed:
            rows.append(parsed)
    rows.sort(key=lambda item: (item["process"].lower(), item["local"], item["remote"]))
    return rows


def collect_linux_arp_rows():
    output = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_addr = parts[0]
        interface = parts[2] if len(parts) > 2 else "---"
        mac_addr = "---"
        state = parts[-1] if parts else "---"
        if "lladdr" in parts:
            lladdr_index = parts.index("lladdr")
            if lladdr_index + 1 < len(parts):
                mac_addr = parts[lladdr_index + 1]
        rows.append(
            {
                "ip": ip_addr,
                "mac": mac_addr,
                "interface": interface,
                "flags": state,
            }
        )
    rows.sort(key=lambda item: (item["interface"], item["ip"]))
    return rows


def render_arp_table(title, rows):
    print(f"\n {G}>>> {title}{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'INTERFACE':<10} {'STATE':<18}")
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
    print(" [!] Collecting full network configuration (ip addr, route, dns)...")
    if not ensure_commands("ip"):
        return
    
    cmd = "echo '--- ADRESY IP ---'; ip addr show; echo '\n--- TRASY (ROUTING) ---'; ip route show; echo '\n--- DNS (RESOLV.CONF) ---'; cat /etc/resolv.conf"
    cmd = "echo '--- IP ADDRESSES ---'; ip addr show; echo '\n--- ROUTES ---'; ip route show; echo '\n--- DNS (RESOLV.CONF) ---'; cat /etc/resolv.conf"
    res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
    
    print(res)
    core_report.save(res, "IPConfig_All_Linux")
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
        if not ensure_commands("ss"):
            return
        
        c = input("\n Selection: ")
        if c == '0': break
        
        if c not in ("1", "2"):
            continue

        core_config.clear_screen()
        established_only = c == "1"
        title = "ACTIVE TCP CONNECTIONS" if established_only else "LISTENING PORTS"
        rows = collect_linux_connections(established_only=established_only)
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
        
        if input("\n [?] Save report? (y/n): ").lower() == 'y':
            core_report.save("\n".join(report_lines), "Session_Audit_Linux")
        
        input("\n Enter...")

def run_arp():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                        {Y}ARP TABLE{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Collecting layer 2 / layer 3 neighbors...\n")
    if not ensure_commands("ip"):
        return
    rows = collect_linux_arp_rows()
    render_arp_table("ARP NEIGHBORS", rows)
    report_lines = [
        "ARP TABLE",
        "",
        "IP Address | MAC Address | Interface | State",
        *[f"{row['ip']} | {row['mac']} | {row['interface']} | {row['flags']}" for row in rows],
    ]
    if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
        core_report.save("\n".join(report_lines), "ARP_Table_Linux")
    input("\n Enter...")
