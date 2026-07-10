#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import time

import core_config


def run():
    core_config.clear_screen()
    print(" [!] Flushing DNS cache (macOS)...")
    cmds = [
        ["sudo", "dscacheutil", "-flushcache"],
        ["sudo", "killall", "-HUP", "mDNSResponder"],
    ]

    done = False
    for cmd in cmds:
        try:
            if subprocess.call(cmd, stderr=subprocess.DEVNULL) == 0:
                print(f" [OK] Executed: {' '.join(cmd)}")
                done = True
        except Exception:
            pass

    if not done:
        print(" [ERROR] Failed to refresh DNS cache.")
    time.sleep(1.5)
