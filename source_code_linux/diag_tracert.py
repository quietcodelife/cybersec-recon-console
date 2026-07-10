#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import sys

import core_config
import core_utils


def build_trace_command(target):
    if core_utils.command_exists("tracepath"):
        return ["tracepath", "-m", "16", "-l", "1500", target], "tracepath"
    if core_utils.command_exists("traceroute"):
        return ["traceroute", "-m", "16", "-q", "2", "-w", "2", target], "traceroute"
    raise FileNotFoundError


def run():
    while True:
        core_config.clear_screen()
        print("================================================================")
        print("                    ROUTE TRACE (LINUX)")
        print("================================================================")
        print(" Default mode: fast trace with hop and timeout limits.")

        target = input("\n Enter IP address or domain (for example google.com) or [0] to return: ").strip()

        if target == "0" or not target:
            break
        try:
            target = core_utils.validate_host(target)
        except ValueError as exc:
            print(f"\n [!] {exc}")
            input("\n Enter...")
            continue

        print(f"\n [!] Starting route trace to: {target}")
        print(" [!] Preferred tool is 'tracepath', with 'traceroute' as fallback.")
        print(" [!] Limit: 16 hops, 2s timeout per hop. Interrupt with Ctrl+C\n")
        print("-" * 64)

        try:
            process = None
            command, command_name = build_trace_command(target)
            print(f" [i] Active tool: {command_name}\n")
            process = subprocess.Popen(
                command,
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
            print("\n [!] Neither 'tracepath' nor 'traceroute' was found.")
            print(" [!] Install for example: sudo apt install iputils-tracepath traceroute")
        except Exception as exc:
            print(f"\n [!] An error occurred: {exc}")

        print("-" * 64)
        input("\n Done. Press Enter...")
