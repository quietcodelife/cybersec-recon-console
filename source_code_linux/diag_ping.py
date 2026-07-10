#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import core_config
import core_utils

def run_menu():
    while True:
        core_config.clear_screen()
        print("=== PING MENU (LINUX) ===\n [1] Google (x4)\n [2] Google (Continuous)\n [3] Custom (x4)\n [4] Custom (Continuous)")
        print(" [0] Back")
        
        c = input("\n Selection: ")
        if c == '0': break
        
        try:
            if not core_utils.command_exists("ping"):
                raise RuntimeError("Missing required system command: 'ping'.")

            if c == '1':
                subprocess.run(["ping", "-c", "4", "8.8.8.8"])
            elif c == '2':
                subprocess.run(["ping", "8.8.8.8"])
            elif c == '3': 
                adr = core_utils.validate_host(input(" Address: "))
                subprocess.run(["ping", "-c", "4", adr])
            elif c == '4': 
                adr = core_utils.validate_host(input(" Address: "))
                subprocess.run(["ping", adr])
            else:
                continue
            
            input("\n[DONE] Enter...")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"\n [ERROR]: {e}")
            input(" Enter...")
