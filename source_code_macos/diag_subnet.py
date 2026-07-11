#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress

import core_config

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"


def run():
    while True:
        core_config.clear_screen()
        print(f"{C}================================================================{RESET}")
        print(f"                 {Y}SUBNET CALCULATOR{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [i] Calculate network boundaries and host capacity.\n")

        raw_value = input(
            " IPv4 or IPv4/CIDR (for example 192.168.1.55/24 or 192.168.1.55) [0=back]: "
        ).strip()
        if raw_value in ("", "0"):
            break

        try:
            target = raw_value
            if "/" not in raw_value:
                print("\n [1] /24 (255.255.255.0)  [2] /16 (255.255.0.0)  [3] /8  [4] Custom")
                mask_input = input(" CIDR mask: ").strip()
                if mask_input == "1":
                    mask_input = "24"
                elif mask_input == "2":
                    mask_input = "16"
                elif mask_input == "3":
                    mask_input = "8"
                elif mask_input == "4":
                    mask_input = input(" Custom CIDR mask: ").strip()
                target = f"{raw_value}/{mask_input}"

            network = ipaddress.IPv4Network(target, strict=False)
            interface = ipaddress.IPv4Interface(target)
            host_count = network.num_addresses - 2 if network.num_addresses > 2 else 0
            first_host = network.network_address + 1 if host_count else network.network_address
            last_host = network.broadcast_address - 1 if host_count else network.broadcast_address

            print(f"\n {G}>>> CALCULATION SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" IP ADDRESS:     {interface.ip}")
            print(f" NETMASK:        {network.netmask}")
            print(f" CIDR:           /{network.prefixlen}")
            print(f" NETWORK:        {network.network_address}")
            print(f" BROADCAST:      {network.broadcast_address}")
            print(" ----------------------------------------------------------------")
            print(f" HOST RANGE:     {first_host} - {last_host}")
            print(f" HOST COUNT:     {host_count}")
        except Exception as exc:
            print(f"\n [ERROR] Invalid subnet input: {exc}")

        input("\n Enter...")
