import logging
logging.disable(logging.CRITICAL)

import re
from androguard.core.apk import APK
from logger_silencer import silence_all


class BxssrfMobileParser:
    def __init__(self, apk_path):
        # logging.disable() لوحده بيتلغى جزئيًا لأن androguard بيعيد ضبط
        # الـ loggers بتاعته أثناء التحليل، فبنقفلها هي بالاسم مباشرة
        silence_all()
        self.apk = APK(apk_path)
        silence_all()  # نكررها بعد الـ init لأن androguard بيسجل loggers جداد أثناء التحليل
        self.manifest = self.apk.get_android_manifest_xml()

    # =========================
    # Attack Surface
    # =========================
    def get_attack_surface(self):
        results = []

        app = self.manifest.find("application")

        debuggable = app.get('{http://schemas.android.com/apk/res/android}debuggable')
        backup = app.get('{http://schemas.android.com/apk/res/android}allowBackup')

        results.append([
            "Manifest",
            "Debuggable",
            debuggable,
            "CRITICAL" if debuggable == "true" else "LOW"
        ])

        results.append([
            "Manifest",
            "AllowBackup",
            backup,
            "HIGH" if backup == "true" else "LOW"
        ])

        return results

    # =========================
    # 🔥 Advanced Extraction
    # =========================
    def extract_sensitive_data(self):
        findings = {
            "URLs": set(),
            "Emails": set(),
            "API Keys": set(),
            "Tokens": set()
        }

        silence_all()  # get_files/get_android_resources كمان بيثيروا logs جداد

        # 1) كل الملفات (بما فيها smali)
        for file in self.apk.get_files():
            if not file.endswith((".xml", ".txt", ".json", ".html", ".js", ".smali")):
                continue

            try:
                content = self.apk.get_file(file)
                text = content.decode("utf-8", errors="ignore")
            except:
                continue

            self._scan(text, findings)

        # 2) strings.xml / resources (مهم جدًا)
        try:
            res = self.apk.get_android_resources()
            strings = res.get_resolved_strings()
            for pkg in strings.values():
                for locale in pkg.values():
                    for s in locale.values():
                        self._scan(str(s), findings)
        except:
            pass

        # تنظيف
        return {k: list(v)[:5] for k, v in findings.items()}

    # =========================
    # Pattern Engine (أقوى)
    # =========================
    def _scan(self, text, findings):
        text = re.sub(r'[\x00-\x1f]+', ' ', text)

        # URLs
        urls = re.findall(r'https?://[^\s"\'<>]+', text)
        for u in urls:
            if "schemas.android.com" not in u:
                findings["URLs"].add(u)

        # Emails
        findings["Emails"].update(
            re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
        )

        # Google API Keys
        findings["API Keys"].update(
            re.findall(r'AIza[0-9A-Za-z\-_]{35}', text)
        )

        # AWS Access Keys
        findings["API Keys"].update(
            re.findall(r'AKIA[0-9A-Z]{16}', text)
        )

        # Generic API Keys
        for _, val in re.findall(r'(?i)(api[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]{8,})', text):
            findings["API Keys"].add(val)

        # JWT Tokens
        findings["Tokens"].update(
            re.findall(r'eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+', text)
        )

        # Bearer / Auth tokens
        for _, val in re.findall(r'(?i)(token|auth|bearer)["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-\._]{10,})', text):
            findings["Tokens"].add(val)
