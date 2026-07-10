#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import time
import core_config
import core_utils

PATH = "/etc/hosts"

def run():
    while True:
        core_config.clear_screen()
        print("=== /ETC/HOSTS EDITOR ===")
        print(" [1] View")
        print(" [2] Add entry (sudo)")
        print(" [3] Edit in nano (sudo)")
        print(" [0] Back")
        
        c = input("\n Selection: ")
        if c == '0': break
        elif c == '1':
            try:
                with open(PATH, "r", encoding="utf-8") as file:
                    print(file.read())
            except Exception as e:
                print(f" [ERROR] {e}")
            input("\n Enter...")
        elif c == '2':
            try:
                ip = core_utils.validate_ipv4(input(" IP: "))
                dom = core_utils.validate_host(input(" Domain: "))
                line = f"{ip} {dom}\n"
                result = subprocess.run(
                    ["sudo", "tee", "-a", PATH],
                    input=line,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode == 0:
                    print(" [OK] Added.")
                else:
                    print(f" [ERROR] Failed to add entry: {result.stderr.strip()}")
            except Exception as e:
                print(f" [ERROR] {e}")
            time.sleep(1)
        elif c == '3':
            subprocess.run(["sudo", "nano", PATH])
