#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, core_config, core_report, glob

def run():
    core_config.clear_screen()
    print("="*60)
    print("      WIFI SECURITY AUDITOR (LINUX ROOT)")
    print("="*60)
    
    if os.geteuid() != 0:
        print(" [!] ROOT privileges are required (sudo).")
        print(" Wi-Fi passwords on Linux are protected by the system.")
        input("\n Enter..."); return

    paths_to_check = [
        "/etc/NetworkManager/system-connections/",
        "/run/NetworkManager/system-connections/"
    ]
    
    found_any_path = False
    for p in paths_to_check:
        if os.path.exists(p): found_any_path = True
            
    if not found_any_path:
        print(f" [!] NetworkManager directories were not found.")
        print(" The system may be using wpa_supplicant or a different network manager.")
        input(" Enter..."); return

    data = []
    
    for path in paths_to_check:
        if not os.path.exists(path): continue
        
        try:
            files = glob.glob(os.path.join(path, "*"))
            for full_path in files:
                try:
                    with open(full_path, 'r') as file:
                        content = file.read()
                        
                        ssid = None
                        psk = None
                        key_mgmt = "Open"
                        current_section = ""
                        
                        for line in content.splitlines():
                            line = line.strip()
                            if line.startswith("[") and line.endswith("]"):
                                current_section = line
                            
                            if current_section == "[wifi]":
                                if line.startswith("ssid="): 
                                    ssid = line.split("=")[1].strip()
                                    
                            if current_section == "[wifi-security]":
                                if line.startswith("psk="): 
                                    psk = line.split("=")[1].strip()
                                if line.startswith("key-mgmt="):
                                    key_mgmt = line.split("=")[1].strip()
                        
                        if ssid:
                            entry = (ssid, key_mgmt, psk if psk else "[NONE / SYSTEM]")
                            if entry not in data:
                                data.append(entry)
                except: pass
        except: pass

    if not data:
        print("\n [!] No saved profiles were found.")
        print(" If you are on a live USB environment, connect to a network and try again.")
    else:
        print(f" {'SSID':<30} | {'TYPE':<15} | {'PASSWORD'}")
        print("-" * 65)
        
        res_txt = ""
        for ssid, typ, pwd in data:
            line = f" {ssid:<30} | {typ:<15} | {pwd}"
            print(line)
            res_txt += line + "\n"
            
        if input("\n Save report? (y/n): ").lower() == 'y':
            core_report.save(res_txt, "WiFi_Passwords_Linux")
        
    input("\n Enter...")
