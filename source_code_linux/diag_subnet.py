#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, ipaddress, time, core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

def run():
    while True:
        core_config.clear_screen()
        print(f"{C}================================================================{RESET}")
        print(f"                 {Y}SUBNET CALCULATOR{RESET}")
        print(f"{C}================================================================{RESET}")
        
        raw = input("\n Enter IP with mask (for example 192.168.1.55/24)\n or IP only (you will be prompted for the mask): ").strip()
        
        if not raw or raw == '0': break
        
        try:
            target = raw
            if "/" not in raw:
                print("\n [1] /24 (255.255.255.0)   [2] /16 (255.255.0.0)   [3] /8")
                mask_input = input(" Enter mask (CIDR, for example 24): ").strip()
                
                if mask_input == '1': mask_input = '24'
                elif mask_input == '2': mask_input = '16'
                elif mask_input == '3': mask_input = '8'
                
                target = f"{raw}/{mask_input}"

            net = ipaddress.IPv4Network(target, strict=False)
            ip_obj = ipaddress.IPv4Interface(target)
            
            total_hosts = net.num_addresses - 2 if net.num_addresses > 2 else 0

            print(f"\n {G}>>> CALCULATION RESULT:{RESET}")
            print(f" ----------------------------------------------------------------")
            print(f" IP ADDRESS:     {ip_obj.ip}")
            print(f" MASK (CIDR):    {net.netmask} (/{net.prefixlen})")
            print(f" NETWORK ADDR:   {C}{net.network_address}{RESET}")
            print(f" BROADCAST:      {C}{net.broadcast_address}{RESET}")
            print(f" ----------------------------------------------------------------")
            print(f" HOST RANGE:     {Y}{net.network_address+1} - {net.broadcast_address-1}{RESET}")
            print(f" HOST COUNT:     {G}{total_hosts}{RESET}")
            print(f" ----------------------------------------------------------------")

        except Exception as e:
            print(f"\n {R}[ERROR] Invalid format: {e}{RESET}")
            
        input("\n Press Enter (or use '0' in the IP field to exit)...")
