#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import sys

import core_config
import core_utils


def run():
    while True:
        core_config.clear_screen()
        print("================================================================")
        print("                    ROUTE TRACE (TRACEROUTE)")
        print("================================================================")
        print(" Default mode: fast trace with hop and timeout limits.")

        target = input("\n Enter IP address or domain or [0] to return: ").strip()
        if target in ("", "0"):
            break

        try:
            target = core_utils.validate_host(target)
        except ValueError as exc:
            print(f"\n [!] {exc}")
            input("\n Enter...")
            continue

        print(f"\n [!] Starting traceroute to: {target}\n")
        print(" [!] Limit: 16 hops, 2 probes per hop, 2s timeout. Interrupt with Ctrl+C")
        print("-" * 64)

        try:
            if not core_utils.command_exists("traceroute"):
                raise FileNotFoundError
            process = None
            process = subprocess.Popen(
                ["traceroute", "-m", "16", "-q", "2", "-w", "2", target],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    print(f" {line.strip()}")
                    sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n\n [!] Interrupted by user.")
            if process:
                process.terminate()
        except FileNotFoundError:
            print("\n [!] The 'traceroute' command was not found.")
        except Exception as exc:
            print(f"\n [!] An error occurred: {exc}")

        print("-" * 64)
        input("\n Done. Press Enter...")
