#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import sys

import core_config
import core_report
import core_utils

C, Y, G, R, RESET = "\033[96m", "\033[93m", "\033[92m", "\033[91m", "\033[0m"


def run():
    while True:
        core_config.clear_screen()
        print(f"{C}================================================================{RESET}")
        print(f"                     {Y}ROUTE TRACE{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [i] Fast traceroute with capped hops and timeout.\n")

        raw_value = input(" Host or domain (for example example.com) [0=back]: ").strip()
        if raw_value in ("", "0"):
            break

        try:
            target = core_utils.validate_host(raw_value)
        except ValueError as exc:
            print(f"\n [ERROR] {exc}")
            input("\n Enter...")
            continue

        if not core_utils.command_exists("traceroute"):
            print("\n [ERROR] The 'traceroute' command was not found.")
            input("\n Enter...")
            return

        print(f"\n {G}>>> TRACE SUMMARY{RESET}")
        print(" ----------------------------------------------------------------")
        print(f" TARGET:         {target}")
        print(" TOOL:           traceroute")
        print(" HOP LIMIT:      16")
        print(" PROBES/HOP:     2")
        print(" TIMEOUT:        2 seconds")
        print(" ----------------------------------------------------------------")
        print("\n [i] Running live route trace. Press Ctrl+C to stop.\n")

        report_lines = [f"Route trace for: {target}", ""]
        process = None
        interrupted = False

        try:
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
                    cleaned = line.rstrip()
                    print(f" {cleaned}")
                    report_lines.append(cleaned)
                    sys.stdout.flush()
        except KeyboardInterrupt:
            interrupted = True
            print("\n\n [WARN] Trace interrupted by the operator.")
            if process:
                process.terminate()
        except Exception as exc:
            print(f"\n [ERROR] {exc}")
        finally:
            if interrupted:
                report_lines.append("")
                report_lines.append("Trace interrupted by the operator.")

        if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
            core_report.save("\n".join(report_lines), f"Route_Trace_{target}")
        input("\n Enter...")
