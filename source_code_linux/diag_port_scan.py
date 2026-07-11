#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket

import core_config
import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def print_banner():
    print(f"{C}================================================================{RESET}")
    print(f"                  {Y}NETWORK PORT SCANNER{RESET}")
    print(f"{C}================================================================{RESET}")


def run():
    common_ports = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        80: "HTTP",
        443: "HTTPS",
        3306: "MYSQL",
        8080: "HTTP-PROXY",
        5432: "POSTGRESQL",
        3389: "RDP",
    }

    while True:
        try:
            core_config.clear_screen()
            print_banner()
            raw_value = input("\n Host or IP (optionally host:port) [0=back]: ").strip()
            if raw_value in ("", "0"):
                break

            target_port = None
            if ":" in raw_value:
                target, port_part = raw_value.split(":", 1)
                try:
                    target_port = int(port_part)
                except ValueError:
                    target = raw_value
            else:
                target = raw_value

            target = core_utils.validate_host(target)
            ports_to_scan = dict(common_ports)
            if target_port:
                ports_to_scan = {target_port: ports_to_scan.get(target_port, "USER")}

            print(f"\n [i] Scanning {target}...\n")
            print(f" {G}>>> PORT SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" TARGET:         {target}")
            print(f" PORT COUNT:     {len(ports_to_scan)}")
            print(" ----------------------------------------------------------------")

            report_lines = [f"Port scan report for: {target}", ""]
            for port, service in sorted(ports_to_scan.items()):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                try:
                    result = sock.connect_ex((target, port))
                    state = "OPEN" if result == 0 else "CLOSED"
                    print(f" [{port:>5}] {state:<8} {service}")
                    report_lines.append(f"{port} {state} {service}")
                except Exception as exc:
                    print(f" [{port:>5}] ERROR    {exc}")
                    report_lines.append(f"{port} ERROR {exc}")
                finally:
                    sock.close()

            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save("\n".join(report_lines), f"PortScan_{target.replace('.', '_')}")
            input("\n Enter...")
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"\n [ERROR] {exc}")
            input("\n Enter...")
