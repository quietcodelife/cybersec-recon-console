import os
import re
import socket
import subprocess
import time

import core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

def get_live_ping():
    try:
        # Linux ping
        cmd = "ping -c 1 -W 1 8.8.8.8"
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
        match = re.search(r"time=([\d\.]+) ms", res, re.IGNORECASE)
        if match:
            return int(float(match.group(1)))
        return -1
    except:
        return -1

def get_adapters_data():
    """Read interface statistics directly from /sys/class/net on Linux."""
    data = {}
    try:
        ifaces = os.listdir('/sys/class/net/')
        for iface in ifaces:
            if iface == 'lo': 
                continue
            
            data[iface] = {'rx': 0, 'tx': 0, 'ip': 'No IP'}
            
            # Pobieranie IP (ip -4 addr show)
            cmd_ip = f"ip -4 addr show {iface}"
            res_ip = subprocess.run(cmd_ip, capture_output=True, text=True, shell=True).stdout
            match_ip = re.search(r"inet\s+([\d\.]+)", res_ip)
            if match_ip:
                data[iface]['ip'] = match_ip.group(1)
                
            try:
                with open(f"/sys/class/net/{iface}/statistics/rx_bytes", "r") as f:
                    data[iface]['rx'] = int(f.read().strip())
                with open(f"/sys/class/net/{iface}/statistics/tx_bytes", "r") as f:
                    data[iface]['tx'] = int(f.read().strip())
            except: pass
    except: pass
    return data

def format_speed(bytes_per_sec):
    if bytes_per_sec >= 1024 * 1024:
        return f"{bytes_per_sec / 1024 / 1024:>6.1f} MB/s"
    elif bytes_per_sec >= 1024:
        return f"{bytes_per_sec / 1024:>6.1f} KB/s"
    else:
        return f"{bytes_per_sec:>6.0f} B/s "

def run():
    core_config.clear_screen()
    print(f"{C}================================================================{RESET}")
    print(f"                  {Y}OPERATIONS DASHBOARD{RESET}")
    print(f"{C}================================================================{RESET}")

    adapters = core_config.get_adapters_info()
    iface_names = list(adapters.keys())
    if not iface_names:
        print(f"\n [ERROR] No network interfaces were detected on this system.")
        time.sleep(2)
        return

    print(" [i] Monitoring active interfaces automatically.")
    print(" [i] Use Ctrl+C to return to the main console.\n")

    hostname = socket.gethostname()
    prev_data = get_adapters_data()
    last_time = time.time()
    time.sleep(1)

    while True:
        try:
            current_time = time.time()
            delta_t = current_time - last_time
            
            p = get_live_ping()
            net_data = get_adapters_data()
            
            if p == -1:
                ping_str = f"{R}NO INTERNET / TIMEOUT{RESET}"
            elif p < 40:
                ping_str = f"{G}{p} ms (LOW RTT){RESET}"
            elif p < 100:
                ping_str = f"{Y}{p} ms (MEDIUM RTT){RESET}"
            else:
                ping_str = f"{R}{p} ms (HIGH RTT){RESET}"

            core_config.clear_screen()
            print(f"{C}================================================================{RESET}")
            print(f"                  {Y}OPERATIONS DASHBOARD{RESET}")
            print(f"{C}================================================================{RESET}")
            active_adapters = [name for name, info in adapters.items() if info["status"] == "UP"]
            print(f" {G}>>> RUNTIME SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" HOSTNAME:       {hostname}")
            print(f" WAN STATUS:     {ping_str}")
            print(f" INTERFACES:     {len(adapters)} total / {len(active_adapters)} active")
            print(" ----------------------------------------------------------------")

            print(f"\n {G}>>> INTERFACE SNAPSHOT{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" {'NAME':<12} {'IPV4':<16} {'RX LIVE':<12} {'TX LIVE':<12} {'RX TOTAL':<10} {'TX TOTAL':<10}")
            print(" " + "-" * 82)

            has_data = False
            for name in iface_names:
                info = net_data.get(name, {})
                prev_info = prev_data.get(name, {})
                
                ip = info.get('ip', '---')
                rx_bytes = info.get('rx', 0)
                tx_bytes = info.get('tx', 0)
                
                prev_rx = prev_info.get('rx', rx_bytes)
                prev_tx = prev_info.get('tx', tx_bytes)

                rx_speed = max(0, (rx_bytes - prev_rx) / delta_t) if delta_t > 0 else 0
                tx_speed = max(0, (tx_bytes - prev_tx) / delta_t) if delta_t > 0 else 0

                rx_total_mb = rx_bytes / 1024 / 1024
                tx_total_mb = tx_bytes / 1024 / 1024

                status = adapters.get(name, {}).get("status", "DOWN")
                if status == "UP" or rx_bytes or tx_bytes or ip != "No IP":
                    has_data = True

                if status != "UP" and rx_bytes == 0 and tx_bytes == 0 and ip in ("---", "No IP"):
                    continue

                print(
                    f" {name[:12]:<12} "
                    f"{ip[:16]:<16} "
                    f"{format_speed(rx_speed):<12} "
                    f"{format_speed(tx_speed):<12} "
                    f"{rx_total_mb:>7.1f} MB "
                    f"{tx_total_mb:>7.1f} MB"
                )

            if not has_data:
                print(" No active interface telemetry is currently available.")

            print(f"\n {Y}[i]{RESET} Auto-refresh enabled. Press {R}Ctrl+C{RESET} to return.")

            prev_data = net_data
            last_time = current_time

            time.sleep(1.5)

        except KeyboardInterrupt:
            print(f"\n {G}[i] Closing dashboard. Returning to the menu...{RESET}")
            time.sleep(1)
            break
        except Exception as e:
            print(f"\n {R}[!] Critical dashboard error: {e}{RESET}")
            time.sleep(2)
            break
