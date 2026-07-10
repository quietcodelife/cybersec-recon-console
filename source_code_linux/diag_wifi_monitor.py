#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, time, sys
import core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

def get_realtime_wifi():
    """
    Read data directly from the Linux kernel (/proc/net/wireless),
    bypassing NetworkManager cache.
    """
    results = []
    try:
        with open("/proc/net/wireless", "r") as f:
            lines = f.readlines()
            for line in lines[2:]:
                parts = line.split()
                if len(parts) > 4:
                    iface = parts[0].replace(":", "")
                    
                    raw_link = parts[2].replace(".", "")
                    raw_level = parts[3].replace(".", "")
                    
                    try:
                        link_val = int(raw_link)
                        level_val = int(raw_level)
                    except: continue
                    
                    results.append({
                        "iface": iface,
                        "link": link_val,
                        "level": level_val
                    })
    except FileNotFoundError:
        pass
    return results

def run():
    try:
        while True:
            core_config.clear_screen()
            print(f"{C}================================================================{RESET}")
            print(f"             {Y}WIFI SIGNAL MONITOR (KERNEL REALTIME){RESET}")
            print(f"{C}================================================================{RESET}")
            
            stats = get_realtime_wifi()
            
            if not stats:
                print(f"\n {R}[!] No Wi-Fi data available.{RESET}")
                print(" 1. In VirtualBox, Wi-Fi may appear as Ethernet (eth0).")
                print("    In that case there is no signal metric and it may appear fixed.")
                print(" 2. Drivers may be missing or the wireless interface may be disabled.")
            else:
                print(f" {'INTERFACE':<12} | {'QUALITY':<20} | {'DBM':<6} | {'RATING'}")
                print("-" * 64)
                
                for s in stats:
                    max_qual = 70.0
                    percent = int((s['link'] / max_qual) * 100)
                    if percent > 100: percent = 100
                    
                    bar_len = int(percent / 5)
                    bar_str = "█" * bar_len + "░" * (20 - bar_len)
                    
                    col = G
                    rating = "EXCELLENT"
                    if s['level'] < -60: 
                        col = Y; rating = "GOOD"
                    if s['level'] < -75: 
                        col = R; rating = "WEAK"
                        
                    print(f" {s['iface']:<12} | {col}[{bar_str}]{RESET} | {s['level']} | {col}{rating}{RESET}")
                    
            print(f"\n {C}[i]{RESET} Refreshing every 1s... (Ctrl+C to exit)")
            time.sleep(1)
            
    except KeyboardInterrupt: pass
