#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, time, core_config

G, R, C, Y, RESET = '\033[92m', '\033[91m', '\033[96m', '\033[93m', '\033[0m'

def save(content, filename_prefix="Report"):
    ts = time.strftime("%Y%m%d_%H%M%S")
    full_name = f"{filename_prefix}_{ts}.txt"
    file_path = os.path.join(core_config.REPORTS_DIR, full_name)
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"\n {G}[SUCCESS]{RESET} Analytical artifact saved.")
        print(f" File: {file_path}")
    except Exception as e:
        print(f"\n {R}[ERROR]{RESET} {e}")
