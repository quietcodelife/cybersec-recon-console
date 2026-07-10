import os
import re
import subprocess
import sys

import core_utils


def clear_screen():
    os.system("clear")


if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.realpath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_DIR = os.path.join(BASE_DIR, "core_data")
REPORTS_DIR = os.path.join(BASE_DIR, "Reports")

APP_ID = "CyberSec Recon Console"
APP_PLATFORM = "macos"

FIRST_RUN_FLAG = os.path.join(DB_DIR, "installed.flag")
DB_IP = os.path.join(DB_DIR, "ip_registry.sys")
DB_WOL = os.path.join(DB_DIR, "wol_registry.sys")
DB_WIFI = os.path.join(DB_DIR, "wifi_vault.dat")


def init():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR, mode=0o755)
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, mode=0o755)
    for path in [DB_IP, DB_WOL]:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as file:
                file.write("")


def get_macos_speed(interface_name):
    if core_utils.command_exists("networksetup"):
        try:
            output = subprocess.check_output(
                ["networksetup", "-getMedia", interface_name],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            match = re.search(r"(\d+(?:baseT|GbaseT|Mb/s|Gb/s))", output, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception:
            pass
    return "--"


def get_adapters_info():
    info = {}
    try:
        interfaces = subprocess.check_output(["ifconfig", "-l"], text=True).strip().split()
    except Exception:
        return {}

    for iface in interfaces:
        if iface.startswith("lo"):
            continue

        try:
            output = subprocess.check_output(["ifconfig", iface], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            continue

        status_match = re.search(r"status:\s+(\w+)", output, re.IGNORECASE)
        status_raw = status_match.group(1).lower() if status_match else "unknown"
        status = "UP" if status_raw in ("active", "unknown") else "DOWN"

        inet_match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", output)
        ip_addr = inet_match.group(1) if inet_match else "---"

        info[iface] = {
            "status": status,
            "speed": get_macos_speed(iface) if status == "UP" else "--",
            "up": status == "UP",
            "ip": ip_addr,
        }
    return info
