import logging

# 🔥 اقفل أي لوجز نهائي (خصوصًا androguard)
logging.disable(logging.CRITICAL)

from manifest_parser import BxssrfMobileParser

# Dynamic (Frida)
try:
    from frida_runner import run_frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


def run_full_pipeline(apk_path, package_name=None):
    """
    Full Pipeline:
    1) Static Analysis
    2) Sensitive Data Extraction
    3) Dynamic Analysis (Frida)
    """

    results = []
    sensitive_data = {}

    try:
        # 🔹 Load Parser
        parser = BxssrfMobileParser(apk_path)

        # 🔹 Static Analysis
        results = parser.get_attack_surface()

        # 🔹 Sensitive Data (deep scan)
        sensitive_data = parser.extract_sensitive_data()

    except Exception as e:
        print(f"[!] Error during static analysis: {e}")

    # 🔥 Dynamic Analysis (Frida)
    if package_name and FRIDA_AVAILABLE:
        try:
            print("\n[*] Running Dynamic Analysis with Frida...\n")
            run_frida(package_name)
        except Exception as e:
            print(f"[!] Frida Error: {e}")

    elif package_name and not FRIDA_AVAILABLE:
        print("[!] Frida not installed or frida_runner.py missing")

    return results, sensitive_data
