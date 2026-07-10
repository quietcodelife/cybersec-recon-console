#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, time, socket, core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'
DB_PATH = core_config.DB_WOL

def load_wol_profiles():
    if not os.path.exists(DB_PATH): return []
    profiles = []
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(";")
                while len(parts) < 4: parts.append("-")
                profiles.append([parts[0], parts[1], parts[2], parts[3]])
    except: pass
    return profiles

def save_wol_profiles(profiles):
    try:
        with open(DB_PATH, "w", encoding="utf-8") as f:
            for p in profiles:
                f.write(f"{p[0]};{p[1]};{p[2]};{p[3]}\n")
    except: pass

def send_magic_packet(mac, ip_bcast="255.255.255.255"):
    mac_clean = mac.replace(":", "").replace("-", "")
    if len(mac_clean) != 12: return False, "Invalid MAC address"
    try:
        data = bytes.fromhex("FF" * 6 + mac_clean * 16)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, (ip_bcast, 9))
        sock.close()
        return True, "Magic Packet sent"
    except Exception as e: return False, str(e)

def manual_input_wol(old=None):
    cur = old if old else ["PC", "", "192.168.1.255", "-"]
    print(f"\n{Y}--- WOL PROFILE WIZARD ---{RESET}")
    n = input(f" Name [{cur[0]}]: ") or cur[0]
    m = input(f" MAC [{cur[1]}]: ") or cur[1]
    i = input(f" IP/Broadcast [{cur[2]}]: ") or cur[2]
    p = input(f" Password (SSH/RPC) [Enter=keep current]: ")
    return [n, m, i, p if p else cur[3]]

def run():
    while True:
        profs = load_wol_profiles()
        core_config.clear_screen()
        print(f"{C}=== WAKE ON LAN MANAGER ==={RESET}")
        print(f" {'ID':<3} | {'NAME':<15} | {'MAC':<17} | {'IP':<15} | {'PASSWORD'}")
        print("-" * 65)
        for i, p in enumerate(profs, 1):
            pwd = p[3]
            print(f" {i:<3} | {p[0]:<15} | {p[1]:<17} | {p[2]:<15} | {pwd}")
        print("-" * 65)
        print(f" [ID] Wake  [A] Add  [E] Edit  [D] Delete  [0] Back")
        
        c = input("\n Selection: ").lower()
        if c == '0': break
        elif c == 'a': 
            d = manual_input_wol()
            if d: profs.append(d); save_wol_profiles(profs)
        elif c == 'd':
            try: 
                idx = int(input(" ID: "))-1
                if 0<=idx<len(profs): del profs[idx]; save_wol_profiles(profs)
            except: pass
        elif c == 'e':
            try:
                idx = int(input(" ID: "))-1
                if 0<=idx<len(profs): 
                    d = manual_input_wol(profs[idx])
                    if d: profs[idx]=d; save_wol_profiles(profs)
            except: pass
        else:
            try:
                idx = int(c)-1
                if 0<=idx<len(profs):
                    res, msg = send_magic_packet(profs[idx][1], profs[idx][2])
                    print(f" {G if res else R}{msg}{RESET}"); time.sleep(1.5)
            except: pass
