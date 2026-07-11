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


def render_interface_summary_table(rows):
    print(f"\n {G}>>> INTERFACE SNAPSHOT{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" {'NAME':<10} {'STATE':<10} {'IPV4':<18} {'SPEED':<12}")
    print(" " + "-" * 56)
    if not rows:
        print(" No data.")
        return
    for row in rows:
        print(
            f" {truncate(row['name'], 10):<10} "
            f"{truncate(row['state'], 10):<10} "
            f"{truncate(row['ip'], 18):<18} "
            f"{truncate(row['speed'], 12):<12}"
        )


def collect_macos_dns_servers(output):
    servers = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver[") and ":" in stripped:
            value = stripped.split(":", 1)[1].strip()
            if value and value not in servers:
                servers.append(value)
    return servers


def collect_macos_default_routes(output):
    ipv4 = None
    ipv6 = []
    in_ipv6 = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "Internet6:":
            in_ipv6 = True
            continue
        if not stripped:
            continue
        if not in_ipv6 and stripped.startswith("default"):
            parts = stripped.split()
            if len(parts) >= 4:
                ipv4 = {"gateway": parts[1], "interface": parts[3]}
        elif in_ipv6 and stripped.startswith("default"):
            parts = stripped.split()
            if len(parts) >= 4:
                ipv6.append({"gateway": parts[1], "interface": parts[3]})
    return ipv4, ipv6


def run_ipconfig():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                  {Y}INTERFACE CENSUS{RESET}")
    print(f"{C}================================================================{RESET}")
    print(" [i] Collecting full network configuration...\n")
    if not ensure_commands("ifconfig", "networksetup"):
        return

    ifconfig_output = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    routes_output = subprocess.run(["netstat", "-rn"], capture_output=True, text=True).stdout
    dns_output = subprocess.run(["scutil", "--dns"], capture_output=True, text=True).stdout

    adapters = core_config.get_adapters_info()
    rows = [
        {
            "name": name,
            "state": info.get("status", "---"),
            "ip": info.get("ip", "---"),
            "speed": info.get("speed", "---"),
        }
        for name, info in sorted(adapters.items(), key=lambda item: (not item[1].get("up", False), item[0]))
    ]
    active_count = sum(1 for item in rows if item["state"] == "UP")
    default_ipv4, default_ipv6 = collect_macos_default_routes(routes_output)
    dns_servers = collect_macos_dns_servers(dns_output)

    print(f" {G}>>> CENSUS SUMMARY{RESET}")
    print(" ----------------------------------------------------------------")
    print(f" PLATFORM:       macOS")
    print(f" INTERFACES:     {len(rows)} total / {active_count} active")
    print(
        f" DEFAULT IPV4:   "
        f"{default_ipv4['gateway']} via {default_ipv4['interface']}" if default_ipv4 else " DEFAULT IPV4:   No data"
    )
    print(f" DNS SERVERS:    {len(dns_servers)} discovered")
    print(" ----------------------------------------------------------------")

    render_interface_summary_table(rows)

    print(f"\n {G}>>> ROUTING SNAPSHOT{RESET}")
    print(" ----------------------------------------------------------------")
    if default_ipv4:
        print(f" IPV4 DEFAULT:   {default_ipv4['gateway']} via {default_ipv4['interface']}")
    else:
        print(" IPV4 DEFAULT:   No data")
    if default_ipv6:
        for route in default_ipv6[:4]:
            print(f" IPV6 DEFAULT:   {route['gateway']} via {route['interface']}")
    else:
        print(" IPV6 DEFAULT:   No data")

    print(f"\n {G}>>> DNS RESOLVERS{RESET}")
    print(" ----------------------------------------------------------------")
    if dns_servers:
        for server in dns_servers:
            print(f" - {server}")
    else:
        print(" No DNS servers discovered.")

    full_report = "\n".join(
        [
            "--- INTERFACES ---",
            ifconfig_output.strip(),
            "",
            "--- ROUTES ---",
            routes_output.strip(),
            "",
            "--- DNS ---",
            dns_output.strip(),
        ]
    )

    if input("\n [1] View raw configuration dump, [Enter] skip: ").strip() == "1":
        print()
        print(full_report)
    if input("\n [?] Save full report? (y/n): ").strip().lower() == "y":
        core_report.save(full_report, "IPConfig_All_macOS")
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
