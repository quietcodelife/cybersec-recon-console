import os
import sys
import subprocess
import re
import core_utils

# --- 1. SYSTEM HELPERS ---
def clear_screen():
    os.system('clear')

# --- 2. BASE PATH DETECTION ---
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(os.path.realpath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- 3. MAIN DIRECTORIES ---
DB_DIR = os.path.join(BASE_DIR, "core_data")
REPORTS_DIR = os.path.join(BASE_DIR, "Reports")

# --- 4. APPLICATION DATA ---
APP_ID = "CyberSec Recon Console"
APP_PLATFORM = "linux"

# --- 5. FILE PATHS ---
FIRST_RUN_FLAG = os.path.join(DB_DIR, "installed.flag")
DB_IP = os.path.join(DB_DIR, "ip_registry.sys")
DB_WOL = os.path.join(DB_DIR, "wol_registry.sys") 
DB_WIFI = os.path.join(DB_DIR, "wifi_vault.dat")  

# --- HELPER FUNCTIONS ---
def init():
    if not os.path.exists(DB_DIR): os.makedirs(DB_DIR, mode=0o755)
    if not os.path.exists(REPORTS_DIR): os.makedirs(REPORTS_DIR, mode=0o755)
    for f in [DB_IP, DB_WOL]:
        if not os.path.exists(f):
            with open(f, "w", encoding='utf-8') as file: file.write("")

def get_linux_speed(interface_name):
    try:
        if not core_utils.command_exists("iwconfig"):
            raise FileNotFoundError
        res = subprocess.check_output(["iwconfig", interface_name], stderr=subprocess.DEVNULL).decode()
        match = re.search(r"Bit Rate[=:]\s*([0-9\.]+.*?/s)", res)
        if match: return match.group(1).strip()
    except: pass
    try:
        if not core_utils.command_exists("nmcli"):
            raise FileNotFoundError
        cmd = ["nmcli", "-t", "-f", "WIFI-PROPERTIES.RATE", "dev", "show", interface_name]
        res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
        if res and "--" not in res: return res.replace("Mbit/s", "Mb/s")
    except: pass
    try:
        if not core_utils.command_exists("ethtool"):
            raise FileNotFoundError
        res = subprocess.check_output(["ethtool", interface_name], stderr=subprocess.DEVNULL).decode()
        if "Speed:" in res: 
            val = res.split("Speed:")[1].splitlines()[0].strip()
            if "Unknown" in val: return "1000 Mb/s"
            return val
    except: pass
    try:
        with open(f"/sys/class/net/{interface_name}/speed", "r") as f:
            val = f.read().strip()
            if val.isdigit() and int(val) > 0: return f"{val} Mb/s"
    except: pass
    return "--"

def get_adapters_info():
    info = {}
    try:
        interfaces = os.listdir('/sys/class/net/')
        for iface in interfaces:
            if iface == 'lo': continue 
            try:
                with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
                    st = f.read().strip().lower()
                    status = "UP" if st in ["up", "unknown"] else "DOWN"
            except: status = "DOWN"
            is_up = status == "UP"
            speed = get_linux_speed(iface) if is_up else "--"
            ip_addr = "---"
            try:
                if not core_utils.command_exists("ip"):
                    raise FileNotFoundError
                cmd = ["ip", "-4", "-o", "addr", "show", "dev", iface]
                res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                if "inet" in res:
                    ip_addr = res.split()[3].split('/')[0]
            except: pass
            info[iface] = {
                "status": status, 
                "speed": speed, 
                "up": is_up,
                "ip": ip_addr
            }
        return info
    except: return {}
