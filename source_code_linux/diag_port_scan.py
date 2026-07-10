#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, socket, core_report, core_config
import core_utils

def run():
    while True:
        try:
            core_config.clear_screen()
            print("=== NETWORK PORT SCANNER ===")
            
            raw_input = input("\n Enter IP (or IP:PORT) or [0] to return: ").strip()
            
            if raw_input == '0' or not raw_input: break
            
            target_port = None
            if ":" in raw_input:
                target, port_part = raw_input.split(":", 1)
                try: target_port = int(port_part)
                except: target = raw_input
            else:
                target = raw_input
            target = core_utils.validate_host(target)

            common_ports = {
                20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
                53: "DNS", 67: "DHCP", 80: "HTTP", 443: "HTTPS", 3306: "MYSQL",
                8080: "HTTP-PROXY", 5432: "POSTGRESQL", 3389: "RDP (Win)"
            }
            
            if target_port:
                if target_port not in common_ports: common_ports[target_port] = "USER"
                print(f" [!] Target: {target} (Port: {target_port})")
                ports_to_scan = {target_port: common_ports[target_port]}
            else:
                print(f" [!] Target: {target}")
                ports_to_scan = common_ports

            print(" [!] Scanning... (Ctrl+C interrupts)")
            print("-" * 55)
            
            results = f"Scan report for: {target}\n"
            
            for port, svc in sorted(ports_to_scan.items()):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                try:
                    res = s.connect_ex((target, port))
                    status = "OPEN" if res == 0 else "Closed"
                    mark = " <<<" if res == 0 else ""
                    
                    line = f" Port {port:<6} [{svc:<12}]: {status}{mark}"
                    print(f" [i] {line}")
                    results += line + "\n"
                except Exception as e:
                    print(f" [!] Port error {port}: {e}")
                finally:
                    s.close()

            print("-" * 55)
            if input("\n [?] Save report? (y/n): ").lower() == 'y':
                core_report.save(results, f"PortScan_{target.replace('.','_')}")
            
            input("\n Press Enter to repeat...")
            
        except KeyboardInterrupt: break
        except Exception as e:
            print(f"\n [ERROR]: {e}"); input(" Enter...")
