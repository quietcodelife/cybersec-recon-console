import os, subprocess, core_report, re
import core_utils

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

DNS_SERVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "OpenDNS": "208.67.222.222",
    "Quad9": "9.9.9.9"
}

def run():
    while True:
        os.system('clear')
        print(f"{C}=== DNS RECON ==={RESET}")
        print(f" [{G}1{RESET}] Quick lookup (default server 8.8.8.8)")
        print(f" [{G}2{RESET}] DNS propagation test (multiple global resolvers)")
        print(f" [{R}0{RESET}] Back")

        if not core_utils.command_exists("nslookup"):
            print("\n [ERROR] Missing required command: 'nslookup'.")
            input("\n Press Enter...")
            break
        
        c = input("\nSelection: ")
        if c == '0': break
        
        if c == '1':
            try:
                dom = core_utils.validate_host(input(" Hostname (for example example.com): ").strip())
            except ValueError as e:
                print(f"\n [ERROR] {e}")
                input("\nPress Enter...")
                continue
            res = subprocess.run(["nslookup", dom, "8.8.8.8"], capture_output=True, text=True).stdout
            print(f"\nServer response:\n{res}")
            core_report.save(res, f"DNS_{dom}")
            input("\nPress Enter...")
        
        elif c == '2':
            try:
                dom = core_utils.validate_host(input(" Domain for propagation test: ").strip())
            except ValueError as e:
                print(f"\n [ERROR] {e}")
                input("\nPress Enter...")
                continue
            print(f"\n {Y}[i] Checking DNS propagation for: {dom}{RESET}\n")
            
            results = f"DNS propagation test for: {dom}\n"
            results += "-" * 50 + "\n"
            
            for name, ip in DNS_SERVERS.items():
                print(f" [*] Querying {name:<11} ({ip:<15})...", end="", flush=True)
                try:
                    res = subprocess.run(["nslookup", dom, ip], capture_output=True, text=True).stdout
                    ips = re.findall(r'Address(?:es)?:\s+((?:\d{1,3}\.){3}\d{1,3})', res)
                    valid_ips = [i for i in ips if i != ip]
                    
                    if valid_ips:
                        print(f" {G}OK{RESET} -> {', '.join(valid_ips)}")
                        results += f"{name:12} ({ip:15}) -> {', '.join(valid_ips)}\n"
                    else:
                        print(f" {R}NO RECORD{RESET}")
                        results += f"{name:12} ({ip:15}) -> NO RECORD\n"
                except Exception as e:
                    print(f" {R}ERROR{RESET}")
                    results += f"{name:12} ({ip:15}) -> ERROR ({e})\n"
                    
            print("-" * 55)
            if input(" [?] Save report? (y/n): ").lower() == 'y':
                core_report.save(results, f"DNS_Propagation_{dom}")
