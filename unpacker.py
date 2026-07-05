import subprocess
import os
import shutil

def decompile_apk(apk_path):
    output_dir = apk_path.replace(".apk", "_extracted")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    print(f"\033[1;34m[*] \033[0m Decompiling {apk_path} ...")
    try:
        result = subprocess.run(['apktool', 'd', apk_path, '-o', output_dir], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"\033[1;32m[+]\033[0m Decompiled to: {output_dir}")
            return output_dir
        return None
    except Exception as e:
        print(f"\033[1;31m[!]\033[0m Error: {e}")
        return None

def run(apk_path=None):
    # لو شغال Manual (الخيار 1) ومفيش مسار مبعوت
    if apk_path is None:
        apk_path = input("Enter path to APK: ")

    if os.path.exists(apk_path):
        return decompile_apk(apk_path)
    else:
        print("\033[1;31m[!] File not found.\033[0m")
        return None
