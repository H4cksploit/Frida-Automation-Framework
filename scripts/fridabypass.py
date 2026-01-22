#!/usr/bin/env python3
"""
Frida Detection Bypass Automation
Author: Abdul Basit
Description:
  Automates the bypass of common Frida detection techniques in Android apps.
  - Renames suspicious binaries in /data/local/tmp
  - Sets up ADB port forwarding
  - Injects a Frida bypass script into the target app

Note: For penetration testing and research purposes only.
"""

import subprocess
import sys
import os

# ---- CONFIG ----
TARGET_APP = "com.target.app"   # Replace with your target app package
SAFE_NAME = "mytools"           # New name for frida-server binary
FRIDA_SCRIPT = "frida_bypass.js" # Your bypass script file

# ---- FUNCTIONS ----
def run_cmd(cmd):
    print(f"[+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip())
    return result

def rename_frida_files():
    print("\n[+] Checking for Frida files in /data/local/tmp/")
    # List files
    run_cmd("adb shell ls /data/local/tmp/")
    # Files to check
    bad_names = ["frida-server", "frida", "re.frida.server"]
    for name in bad_names:
        check = run_cmd(f"adb shell ls /data/local/tmp/{name}")
        if check.returncode == 0:
            print(f"[!] Found {name}, renaming to {SAFE_NAME}")
            run_cmd(f"adb shell mv /data/local/tmp/{name} /data/local/tmp/{SAFE_NAME}")

def setup_port_forwarding():
    print("\n[+] Setting up port forwarding")
    run_cmd("adb forward tcp:27044 tcp:27042")
    run_cmd("adb forward tcp:27045 tcp:27043")

def inject_frida_script():
    print("\n[+] Starting Frida with bypass script")
    run_cmd(f'frida -U -f {TARGET_APP} -l {FRIDA_SCRIPT} --no-pause')

# ---- MAIN ----
if __name__ == "__main__":
    print("[*] Frida Detection Bypass Automation Starting...\n")

    rename_frida_files()
    setup_port_forwarding()
    inject_frida_script()

    print("\n[*] Done! Frida bypass is active.")
