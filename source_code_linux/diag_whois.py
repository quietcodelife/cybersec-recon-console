#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import core_report, core_config

def run():
    while True:
        core_config.clear_screen()
        print("=== WHOIS / DOMAIN REGISTRATION (RDAP) ===\n")
        domain = input(" Enter domain (for example google.com) or [0] to return: ").strip()
        
        if not domain or domain == '0': break
        
        print(f"\n [i] Retrieving data for: {domain}...")
        
        try:
            import requests
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            
            r = requests.get(f"https://rdap.org/domain/{domain}", headers=headers, timeout=10)
            
            if r.status_code == 200:
                data = r.json()
                
                events = data.get('events', [])
                created = "No data"
                expired = "No data"
                
                for e in events:
                    if e.get('eventAction') == 'registration': created = e.get('eventDate')
                    if e.get('eventAction') == 'expiration': expired = e.get('eventDate')
                
                output = f"\n RESULT FOR: {domain.upper()}\n"
                output += f" {'-'*40}\n"
                output += f" REGISTERED:  {created[:10]}\n"
                output += f" EXPIRES:     {expired[:10]}\n"
                output += f" HANDLE:      {data.get('handle', 'N/A')}\n"
                
                statuses = data.get('status', [])
                output += f" STATUS:      {', '.join(statuses)}\n"
                output += f" {'-'*40}\n"
                
                print(output)
                
                if input(" [?] Save report? (y/n): ").lower() == 'y':
                    core_report.save(output, f"Whois_{domain}")
            
            elif r.status_code == 404:
                print(f" [!] Domain {domain} is probably available or does not exist.")
            elif r.status_code == 403:
                print(" [!] Access forbidden (403). The server blocked the request.")
            elif r.status_code == 429:
                print(" [!] Too many requests (rate limit). Please wait and try again.")
            else:
                print(f" [!] API error: {r.status_code}")
                
        except Exception as e:
            print(f" [!] Connection error: {e}")
        
        input("\n Enter...")
