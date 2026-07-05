import subprocess
import time


def send_payload_to_adb(uri_payload, wait_time=2):
    """
    إرسال Deep Link / Intent للتطبيق على الجهاز عبر ADB
    """

    try:
        command = [
            "adb", "shell", "am", "start",
            "-a", "android.intent.action.VIEW",
            "-d", uri_payload
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        # استنى شوية عشان التطبيق يفتح
        time.sleep(wait_time)

        stderr = result.stderr.lower()

        # Detect crash / failure
        if "error" in stderr or "exception" in stderr:
            return False, result.stderr

        return True, result.stdout

    except Exception as e:
        return False, str(e)


def check_adb():
    """
    التأكد إن ADB شغال
    """
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True
        )

        return "device" in result.stdout

    except:
        return False


def install_apk(apk_path):
    """
    تثبيت APK على الجهاز
    """
    try:
        result = subprocess.run(
            ["adb", "install", "-r", apk_path],
            capture_output=True,
            text=True
        )

        if "success" in result.stdout.lower():
            return True, result.stdout

        return False, result.stderr

    except Exception as e:
        return False, str(e)


def launch_app(package_name):
    """
    تشغيل التطبيق
    """
    try:
        subprocess.run(
            ["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            capture_output=True,
            text=True
        )
        return True
    except:
        return False
