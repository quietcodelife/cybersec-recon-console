import os
import subprocess
import re
import core_report

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

DNS_SERVERS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "AdGuard": "94.140.14.14",
    "Control D": "76.76.2.0",
    "Mullvad": "194.242.2.2"
}

def ping_server(ip):
    try:
        cmd = f"ping -c 3 -W 1 {ip}"
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
        
        match = re.search(r"=\s*[\d\.]+/([\d\.]+)/[\d\.]+", res)
        if match:
            return int(float(match.group(1)))
        return 9999
    except Exception:
        return 9999

def draw_bar(latency):
    if latency == 9999:
        return f"{R}[ NO RESPONSE ]{RESET}"
        
    bar_length = 20
    filled = min(int((latency / 100) * bar_length), bar_length)
    
    if latency < 20: color = G
    elif latency < 50: color = Y
    else: color = R
        
    bar = "█" * filled + "░" * (bar_length - filled)
    return f"{color}[{bar}] {latency} ms{RESET}"

def run():
    while True:
        os.system('clear')
        print(f"{C}================================================================{RESET}")
        print(f"                  {Y}DNS BENCHMARK{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [i] This tool tests popular DNS servers to help identify")
        print("     the lowest-latency resolver for your current connection.")
        print("----------------------------------------------------------------")
        
        if input("\n Start test? (y/n): ").strip().lower() != 'y':
            break

        print("\n [*] Testing servers now (this may take several seconds)...\n")
        
        results = []
        for name, ip in DNS_SERVERS.items():
            print(f"     > Pinging: {name:<12} ({ip})...", end="", flush=True)
            latency = ping_server(ip)
            results.append({"name": name, "ip": ip, "latency": latency})
            if latency == 9999: print(f" {R}TIMEOUT{RESET}")
            else: print(f" {G}{latency} ms{RESET}")
                
        results.sort(key=lambda x: x["latency"])
        
        os.system('clear')
        print(f"{C}================================================================{RESET}")
        print(f"                   {Y}DNS SERVER TEST RESULTS{RESET}")
        print(f"{C}================================================================{RESET}")
        print(f" {'PROVIDER':<12} | {'IP ADDRESS':<15} | {'LATENCY'}")
        print("-" * 64)
        
        report_text = "DNS BENCHMARK REPORT\n---------------------------------\n"
        
        for idx, res in enumerate(results, 1):
            name, ip, lat = res["name"], res["ip"], res["latency"]
            bar = draw_bar(lat)
            mark = f"{Y}*{RESET}" if idx == 1 and lat != 9999 else " "
            print(f" {mark}{name:<11} | {ip:<15} | {bar}")
            lat_txt = "TIMEOUT" if lat == 9999 else f"{lat} ms"
            report_text += f"{idx}. {name} ({ip}) - {lat_txt}\n"
            
        print("-" * 64)
        print(f" {Y}[*] Fastest server for your location: {results[0]['name']}{RESET}")
        
        if input("\n [?] Save results to file? (y/n): ").strip().lower() == 'y':
            core_report.save(report_text, "DNS_Benchmark")
            
        input("\n Press Enter to return to the main menu...")
        break
