#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import subprocess

import core_report
import core_config
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
INTERNET_TARGET = "1.1.1.1"
AUXILIARY_PREFIXES = ("tun", "tap", "virbr", "docker", "br-", "veth", "wg", "lo")


def safe_run(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except Exception:
        return None


def parse_gateway():
    if not core_utils.command_exists("ip"):
        return "No data"
    result = safe_run(["ip", "route", "show", "default"])
    if not result:
        return "No data"
    match = re.search(r"default via ([0-9.]+)", result.stdout or "")
    return match.group(1) if match else "No data"


def parse_dns_servers():
    resolvers = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith("nameserver"):
                    value = stripped.split()[1]
                    if value not in resolvers:
                        resolvers.append(value)
    except Exception:
        return []
    return resolvers


def ping_target(target):
    if not target or target == "No data":
        return None
    result = safe_run(["ping", "-c", "1", "-W", "2", target])
    if not result:
        return None
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    match = re.search(r"time[=<]([\d.]+)\s*ms", output, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None


def health_label(gateway_rtt, internet_rtt, active_count):
    if active_count == 0:
        return "No Active Interfaces", R
    if gateway_rtt is None and internet_rtt is None:
        return "Offline / Unreachable", R
    if gateway_rtt is not None and internet_rtt is None:
        return "Local Connectivity Only", Y
    if internet_rtt is not None and internet_rtt < 80:
        return "Healthy", G
    if internet_rtt is not None:
        return "Degraded Latency", Y
    return "Partial Health", Y


def render_rtt(value):
    if value is None:
        return "No response"
    return f"{value:.1f} ms"


def is_primary_interface(name, info):
    if info.get("ip") not in ("---", "", None):
        return True
    lowered = str(name or "").lower()
    return not lowered.startswith(AUXILIARY_PREFIXES)


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}INTERFACE HEALTH SNAPSHOT{RESET}")
        print(f"{C}================================================================{RESET}")
        choice = input("\n Press Enter to collect a health snapshot or [0] to return: ").strip()
        if choice == "0":
            break

        try:
            adapters = core_config.get_adapters_info()
            active = [(name, info) for name, info in sorted(adapters.items()) if info.get("status") == "UP"]
            primary_active = [(name, info) for name, info in active if is_primary_interface(name, info)]
            auxiliary_active = [(name, info) for name, info in active if not is_primary_interface(name, info)]
            gateway = parse_gateway()
            resolvers = parse_dns_servers()
            gateway_rtt = ping_target(gateway)
            internet_rtt = ping_target(INTERNET_TARGET)
            label, color = health_label(gateway_rtt, internet_rtt, len(primary_active))

            print(f"\n {G}>>> HEALTH SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" STATE:          {color}{label}{RESET}")
            print(f" ACTIVE LINKS:   {len(primary_active)} primary / {len(active)} total")
            print(f" DEFAULT GW:     {gateway}")
            print(f" GW RTT:         {render_rtt(gateway_rtt)}")
            print(f" INTERNET RTT:   {render_rtt(internet_rtt)}")
            print(f" DNS COUNT:      {len(resolvers)}")
            print(" ----------------------------------------------------------------")

            print(f"\n {Y}ACTIVE INTERFACES:{RESET}")
            if primary_active:
                for name, info in primary_active:
                    print(f"  - {name}  {info.get('ip', '---')}  {info.get('speed', '--')}")
            else:
                print("  none")

            print(f"\n {Y}AUXILIARY / VIRTUAL LINKS:{RESET}")
            if auxiliary_active:
                for name, info in auxiliary_active[:8]:
                    print(f"  - {name}  {info.get('ip', '---')}  {info.get('speed', '--')}")
                if len(auxiliary_active) > 8:
                    print(f"  ... {len(auxiliary_active) - 8} more")
            else:
                print("  none")

            print(f"\n {Y}DNS RESOLVERS:{RESET}")
            if resolvers:
                for resolver in resolvers[:8]:
                    print(f"  - {resolver}")
            else:
                print("  none")

            print(f"\n {Y}ASSESSMENT:{RESET}")
            if len(primary_active) == 0:
                print("  - No active interfaces were detected on the host.")
            elif gateway_rtt is None:
                print("  - The default gateway did not respond to a single ICMP probe.")
            else:
                print("  - The default gateway responded to the reachability check.")

            if internet_rtt is None:
                print("  - Public internet reachability could not be confirmed with the external probe.")
            else:
                print("  - Public internet reachability was confirmed with the external probe.")

            report_lines = [
                "INTERFACE HEALTH SNAPSHOT",
                "",
                f"State: {label}",
                f"Active Links: {len(primary_active)} primary / {len(active)} total",
                f"Default Gateway: {gateway}",
                f"Gateway RTT: {render_rtt(gateway_rtt)}",
                f"Internet RTT: {render_rtt(internet_rtt)}",
                "",
                "[Active Interfaces]",
                *([f"{name} | {info.get('ip', '---')} | {info.get('speed', '--')}" for name, info in primary_active] or ["none"]),
                "",
                "[Auxiliary / Virtual Links]",
                *([f"{name} | {info.get('ip', '---')} | {info.get('speed', '--')}" for name, info in auxiliary_active] or ["none"]),
                "",
                "[DNS Resolvers]",
                *([resolver for resolver in resolvers] or ["none"]),
            ]

            if input("\n [?] Save results to file? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), "Interface_Health_Snapshot")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
