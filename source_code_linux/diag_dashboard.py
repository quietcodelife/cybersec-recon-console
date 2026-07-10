import os
import time
import subprocess
import socket
import re
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
    os.system('clear')
    print(f"{C}================================================================{RESET}")
    print(f"               {Y}DASHBOARD CONFIGURATION{RESET}")
    print(f"{C}================================================================{RESET}")
    
    adapters = core_config.get_adapters_info()
    iface_names = list(adapters.keys())
    
    if not iface_names:
        print(f" {R}[!] No network interfaces were detected on this system.{RESET}")
        time.sleep(2)
        return

    print(f" {Y}Select interfaces to monitor:{RESET}\n")
    for i, name in enumerate(iface_names, 1):
        st = f"{G}UP{RESET}" if adapters[name]['status'] == "UP" else f"{R}DOWN{RESET}"
        print(f" [{G}{i}{RESET}] {name:<25} ({st})")
        
    print(f"\n [{G}0{RESET}] All active interfaces (auto-detect)")
    
    choices = input("\n Selection (for example 1 or 1,3 or 0): ").strip()
    selected_adapters = []
    
    if choices == '0' or not choices:
        selected_adapters = iface_names 
    else:
        for c in choices.split(','):
            try:
                idx = int(c.strip()) - 1
                if 0 <= idx < len(iface_names):
                    selected_adapters.append(iface_names[idx])
            except: pass
                
    if not selected_adapters:
        selected_adapters = iface_names 
        
    os.system('clear')
    print(f"\n {C}Initializing dashboard...{RESET}")
    print(f" {Y}Collecting initial interface data...{RESET}")
    
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
            
            if p == -1: ping_str = f"{R}NO INTERNET (Timeout){RESET}"
            elif p < 40: ping_str = f"{G}{p} ms (Excellent){RESET}"
            elif p < 100: ping_str = f"{Y}{p} ms (Moderate){RESET}"
            else: ping_str = f"{R}{p} ms (High){RESET}"

            os.system('clear')
            print(f"{C}================================================================{RESET}")
            print(f"              {Y}GLOBAL DASHBOARD (REAL-TIME MONITOR){RESET}")
            print(f"{C}================================================================{RESET}")
            
            print(f" NAZWA HOSTA: {C}{hostname}{RESET}")
            print(f" WAN STATUS:  {ping_str}")
            print(f"{C}----------------------------------------------------------------{RESET}")
            print(f" {Y}NETWORK TRAFFIC AND IP ADDRESSES (selected interfaces):{RESET}\n")
            
            has_data = False
            for name in selected_adapters:
                info = net_data.get(name, {})
                prev_info = prev_data.get(name, {})
                
                ip = info.get('ip', 'No IP (Disconnected)')
                rx_bytes = info.get('rx', 0)
                tx_bytes = info.get('tx', 0)
                
                prev_rx = prev_info.get('rx', rx_bytes)
                prev_tx = prev_info.get('tx', tx_bytes)
                
                if choices in ['0', ''] and rx_bytes == 0 and tx_bytes == 0 and 'No IP' in ip:
                    continue 
                    
                has_data = True
                
                rx_speed = max(0, (rx_bytes - prev_rx) / delta_t) if delta_t > 0 else 0
                tx_speed = max(0, (tx_bytes - prev_tx) / delta_t) if delta_t > 0 else 0
                
                rx_total_mb = rx_bytes / 1024 / 1024
                tx_total_mb = tx_bytes / 1024 / 1024
                
                print(f"  > {C}{name[:22]:<22}{RESET} | IP: {Y}{ip:<15}{RESET}")
                print(f"    {'Speed (Live):':<22} | ↓ {format_speed(rx_speed):<10} | ↑ {format_speed(tx_speed)}")
                print(f"    {'Total Traffic:':<22} | ↓ {rx_total_mb:>6.1f} MB   | ↑ {tx_total_mb:>6.1f} MB\n")
                
            if not has_data:
                print(f"  {R}> No active data available to display (interfaces disconnected?).{RESET}")
                
            print(f"{C}----------------------------------------------------------------{RESET}")
            print(f" Auto-refresh enabled. Press {R}[Ctrl+C]{RESET} to exit.")

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
