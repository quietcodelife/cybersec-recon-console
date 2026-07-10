#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import time

import core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'


def list_interfaces():
    try:
        return sorted([name for name in os.listdir("/sys/class/net") if name != "lo"])
    except Exception:
        return []


def get_bytes(iface):
    try:
        with open(f"/sys/class/net/{iface}/statistics/rx_bytes", "r", encoding="utf-8") as file:
            rx = int(file.read().strip())
        with open(f"/sys/class/net/{iface}/statistics/tx_bytes", "r", encoding="utf-8") as file:
            tx = int(file.read().strip())
        return rx, tx
    except Exception:
        return None


def get_link_state(iface):
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r", encoding="utf-8") as file:
            state = file.read().strip().lower()
        return "UP" if state in ("up", "unknown") else "DOWN"
    except Exception:
        return "UNKNOWN"


def format_rate(bytes_per_sec):
    kb = bytes_per_sec / 1024
    mb = kb / 1024
    if mb >= 1:
        return f"{mb:>7.2f} MB/s"
    return f"{kb:>7.1f} KB/s"


def format_total(byte_count):
    mb = byte_count / 1024 / 1024
    if mb >= 1024:
        return f"{mb / 1024:>7.2f} GB"
    return f"{mb:>7.1f} MB"


def run():
    baseline = {}
    last_time = time.time()

    interfaces = list_interfaces()
    if not interfaces:
        core_config.clear_screen()
        print(f"{R}[ERROR]{RESET} No network interfaces were detected in `/sys/class/net`.")
        input("\n Enter...")
        return

    for iface in interfaces:
        stats = get_bytes(iface)
        if stats is not None:
            baseline[iface] = stats

    while True:
        try:
            core_config.clear_screen()
            now = time.time()
            delta_t = max(now - last_time, 0.001)

            print(f"{C}================================================================{RESET}")
            print(f"                   {Y}LIVE BANDWIDTH TELEMETRY{RESET}")
            print(f"{C}================================================================{RESET}")
            print(" Real-time interface utilization monitor.")
            print(f" Exit: {R}Ctrl+C{RESET}\n")
            print(f" {'INTERFACE':<14} | {'STATE':<7} | {'DOWNLOAD':<12} | {'UPLOAD':<12} | {'RX TOTAL':<10} | {'TX TOTAL':<10}")
            print(f"{C}---------------------------------------------------------------------------------------{RESET}")

            found_any = False
            current = {}
            for iface in list_interfaces():
                stats = get_bytes(iface)
                if stats is None:
                    continue

                found_any = True
                rx, tx = stats
                prev_rx, prev_tx = baseline.get(iface, (rx, tx))
                dl_rate = max(0, (rx - prev_rx) / delta_t)
                ul_rate = max(0, (tx - prev_tx) / delta_t)
                state = get_link_state(iface)
                state_colored = f"{G}{state}{RESET}" if state == "UP" else f"{R}{state}{RESET}"

                print(
                    f" {iface:<14} | {state_colored:<16} | {format_rate(dl_rate):<12} | "
                    f"{format_rate(ul_rate):<12} | {format_total(rx):<10} | {format_total(tx):<10}"
                )
                current[iface] = (rx, tx)

            if not found_any:
                print(f" {R}[NO DATA]{RESET} Failed to read counters for interfaces.")

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
