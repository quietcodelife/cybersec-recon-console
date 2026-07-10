#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import subprocess
import time

import core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'


def get_netstat_counters():
    counters = {}
    completed = subprocess.run(
        ["netstat", "-ib"],
        capture_output=True,
        text=True,
        check=False,
    )
    headers = None
    ibytes_idx = None
    obytes_idx = None
    for line in completed.stdout.splitlines():
        if not line:
            continue
        parts = re.split(r"\s+", line.strip())
        if line.startswith("Name"):
            headers = parts
            try:
                ibytes_idx = headers.index("Ibytes")
                obytes_idx = headers.index("Obytes")
            except ValueError:
                return {}
            continue
        if headers is None or ibytes_idx is None or obytes_idx is None:
            continue
        if len(parts) < len(headers):
            continue
        iface = parts[0]
        if iface.startswith("lo"):
            continue
        try:
            ibytes = int(parts[ibytes_idx])
            obytes = int(parts[obytes_idx])
        except ValueError:
            continue
        except (IndexError, Exception):
            continue
        prev_ibytes, prev_obytes = counters.get(iface, (0, 0))
        counters[iface] = (max(prev_ibytes, ibytes), max(prev_obytes, obytes))
    return counters


def format_rate(bytes_per_sec):
    kb = bytes_per_sec / 1024
    mb = kb / 1024
    if mb >= 1:
        return f"{mb:>7.2f} MB/s"
    return f"{kb:>7.1f} KB/s"


def run():
    baseline = get_netstat_counters()
    last_time = time.time()

    if not baseline:
        core_config.clear_screen()
        print(f"{R}[ERROR]{RESET} Failed to read counters from `netstat -ib`.")
        input("\n Enter...")
        return

    while True:
        try:
            core_config.clear_screen()
            now = time.time()
            delta_t = max(now - last_time, 0.001)
            current = get_netstat_counters()

            print(f"{C}================================================================{RESET}")
            print(f"                   {Y}LIVE BANDWIDTH TELEMETRY{RESET}")
            print(f"{C}================================================================{RESET}")
            print(" Real-time interface utilization monitor.")
            print(f" Exit: {R}Ctrl+C{RESET}\n")
            print(f" {'INTERFACE':<14} | {'DOWNLOAD':<12} | {'UPLOAD':<12} | {'RX TOTAL':<12} | {'TX TOTAL':<12}")
            print(f"{C}--------------------------------------------------------------------------------{RESET}")

            for iface, (ibytes, obytes) in current.items():
                prev_i, prev_o = baseline.get(iface, (ibytes, obytes))
                dl_rate = max(0, (ibytes - prev_i) / delta_t)
                ul_rate = max(0, (obytes - prev_o) / delta_t)
                print(
                    f" {iface:<14} | {format_rate(dl_rate):<12} | {format_rate(ul_rate):<12} | "
                    f"{ibytes / 1024 / 1024:>8.1f} MB | {obytes / 1024 / 1024:>8.1f} MB"
                )

            baseline = current
            last_time = now
            time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n {G}[OK]{RESET} Closing bandwidth telemetry...")
            time.sleep(1)
            break
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} Bandwidth module stopped with an error: {exc}")
            input("\n Enter...")
            break
