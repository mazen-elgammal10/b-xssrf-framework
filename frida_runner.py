import subprocess
import time

def run_frida(package_name):
    print("[*] Starting Frida...")

    cmd = [
        "frida",
        "-U",
        "-f", package_name,
        "-l", "frida_hook.js",
        "--no-pause"
    ]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Stopped")
