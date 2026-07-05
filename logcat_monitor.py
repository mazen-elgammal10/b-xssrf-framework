# logcat_monitor.py

import subprocess
import time


def clear_logcat():
    subprocess.run(["adb", "logcat", "-c"], capture_output=True)


def collect_logs(duration=3):
    """
    يجمع logs لمدة ثواني معينة
    """
    try:
        process = subprocess.Popen(
            ["adb", "logcat", "-d"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(duration)

        output, _ = process.communicate(timeout=5)

        return output

    except Exception:
        return ""
