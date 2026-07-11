import os
import re
import subprocess

import core_report

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

DNS_SERVERS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "AdGuard": "94.140.14.14",
    "Control D": "76.76.2.0",
    "Mullvad": "194.242.2.2",
}


def ping_server(ip_addr):
    try:
        response = subprocess.run(f"ping -c 3 -W 1 {ip_addr}", capture_output=True, text=True, shell=True).stdout
        match = re.search(r"=\s*[\d\.]+/([\d\.]+)/[\d\.]+", response)
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
    color = G if latency < 20 else Y if latency < 50 else R
    bar = "█" * filled + "░" * (bar_length - filled)
    return f"{color}[{bar}] {latency} ms{RESET}"


def run():
    while True:
        os.system("clear")
        print(f"{C}================================================================{RESET}")
        print(f"                   {Y}DNS BENCHMARK{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [i] Compare common public resolvers by latency.\n")

        if input(" Start benchmark? (y/n): ").strip().lower() != "y":
            break

        print("\n [i] Testing DNS servers now...\n")
        results = []
        for name, ip_addr in DNS_SERVERS.items():
            print(f" [*] Pinging {name:<12} ({ip_addr})...", end="", flush=True)
            latency = ping_server(ip_addr)
            results.append({"name": name, "ip": ip_addr, "latency": latency})
            print(f" {R}TIMEOUT{RESET}" if latency == 9999 else f" {G}{latency} ms{RESET}")

        results.sort(key=lambda item: item["latency"])

        print(f"\n {G}>>> BENCHMARK SUMMARY{RESET}")
        print(" ----------------------------------------------------------------")
        print(f" SERVERS TESTED: {len(results)}")
        fastest = results[0]['name'] if results else "No data"
        print(f" FASTEST:        {fastest}")
        print(" ----------------------------------------------------------------")

        print(f"\n {'PROVIDER':<12} {'IP ADDRESS':<15} {'LATENCY'}")
        print(" ----------------------------------------------------------------")
        report_text = ["DNS BENCHMARK REPORT", ""]
        for idx, result in enumerate(results, 1):
            name, ip_addr, latency = result["name"], result["ip"], result["latency"]
            marker = "*" if idx == 1 and latency != 9999 else " "
            print(f" {marker} {name:<10} {ip_addr:<15} {draw_bar(latency)}")
            report_text.append(f"{idx}. {name} ({ip_addr}) - {'TIMEOUT' if latency == 9999 else f'{latency} ms'}")

        if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
            core_report.save("\n".join(report_text), "DNS_Benchmark")

        input("\n Enter...")
        break
