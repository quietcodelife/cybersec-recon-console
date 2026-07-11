#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import subprocess
import time

import core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'


def get_live_ping():
    try:
        res = subprocess.run(["ping", "-c", "1", "1.1.1.1"], capture_output=True, text=True, check=False).stdout
        for token in res.split():
            if token.startswith("time="):
                return int(float(token.split("=")[1]))
        return -1
    except Exception:
        return -1


def run():
    hostname = socket.gethostname()
    while True:
        try:
            core_config.clear_screen()
            ping_ms = get_live_ping()
            adapters = core_config.get_adapters_info()
            active_count = sum(1 for info in adapters.values() if info["status"] == "UP")

            if ping_ms == -1:
                ping_state = f"{R}NO CONNECTIVITY / TIMEOUT{RESET}"
            elif ping_ms < 40:
                ping_state = f"{G}{ping_ms} ms (LOW RTT){RESET}"
            elif ping_ms < 100:
                ping_state = f"{Y}{ping_ms} ms (MEDIUM RTT){RESET}"
            else:
                ping_state = f"{R}{ping_ms} ms (HIGH RTT){RESET}"

            print(f"{C}================================================================{RESET}")
            print(f"                  {Y}OPERATIONS DASHBOARD{RESET}")
            print(f"{C}================================================================{RESET}")
            print(f" {G}>>> RUNTIME SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" HOSTNAME:       {hostname}")
            print(f" WAN STATUS:     {ping_state}")
            print(f" INTERFACES:     {len(adapters)} total / {active_count} active")
            print(" ----------------------------------------------------------------")
            print(f"\n {G}>>> INTERFACE SNAPSHOT{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" {'NAME':<12} {'STATE':<10} {'IPV4':<18} {'SPEED':<12}")
            print(" " + "-" * 58)

            for name in sorted(adapters.keys()):
                info = adapters[name]
                status = f"{G}UP{RESET}" if info["status"] == "UP" else f"{R}DOWN{RESET}"
                print(f" {name:<12} {status:<10} {info['ip']:<18} {info['speed']:<12}")

            print(f"\n {Y}[i]{RESET} Auto-refresh enabled. Press {R}Ctrl+C{RESET} to return.")
            time.sleep(1.5)
        except KeyboardInterrupt:
            print(f"\n {G}[i] Closing dashboard. Returning to the menu...{RESET}")
            time.sleep(1)
            break
        except Exception as exc:
            print(f"\n {R}[!] Critical dashboard error: {exc}{RESET}")
            time.sleep(2)
            break
