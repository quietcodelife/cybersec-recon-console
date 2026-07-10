#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess, time, core_config

def run():
    core_config.clear_screen()
    print(" [!] Flushing DNS cache (systemd-resolved)...")
    cmds = [
        "resolvectl flush-caches",
        "systemd-resolve --flush-caches",
        "service nscd restart"
    ]
    
    done = False
    for c in cmds:
        try:
            if subprocess.call(c, shell=True, stderr=subprocess.DEVNULL) == 0:
                print(f" [OK] Executed: {c.split()[0]}")
                done = True
                break
        except: pass
    
    if not done: print(" [i] No local DNS cache service was found (this can be normal on Linux).")
    time.sleep(1.5)
