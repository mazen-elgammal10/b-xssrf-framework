import os
import re

def run(extraction_dir):
    results = {"secrets": [], "endpoints": [], "injection": []}

    # الكلمات المفتاحية للهجوم
    patterns = {
        # الشكل البرمجي: key = "value" أو key: 'value' (assignment)
        # القيمة محصورة بـ 4-100 حرف وبدون newline، عشان منمسكش method bodies كاملة
        "secrets_assignment": r"(?i)\b(api[_-]?key|password|secret|token|apikey|firebase)\b\s*[:=]\s*['\"]([^'\"\n]{4,100})['\"]",
        # الشكل النصي الحر (زي DIVA): سطر واحد فيه "API Key: xxxx\nAPI Password: yyyy"
        # هنا الـ label والـ value جوه نفس الـ string، متفصلين بـ \n حرفي مش assignment
        # الـ \\ في الـ exclusion class بتوقف الـ match عند أول \n حرفي (backslash+n) في السمالي
        "secrets_labeled": r"(?i)\b(api\s*key|password|secret|token|firebase|user\s*name)\b\s*:\s*([^\"\\\n]{2,80})",
        "endpoints": r"https?://[\w\.-]+",
        "sql": r"(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+"
    }

    for root, _, files in os.walk(extraction_dir):
        for file in files:
            if file.endswith((".smali", ".xml", ".txt")):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', errors='ignore') as f:
                        content = f.read()
                        # فحص السيكرتس والروابط
                        for key, pattern in patterns.items():
                            found = re.findall(pattern, content, re.IGNORECASE)
                            if found:
                                if key in ("secrets_assignment", "secrets_labeled"):
                                    # استخراج القيمة فقط من الـ Tuple، مع اسم الـ label
                                    for label, value in found:
                                        value = value.strip()
                                        if value:
                                            results["secrets"].append(f"{label.strip()}: {value}")
                                elif key == "endpoints":
                                    results["endpoints"].extend(found)
                                elif key == "sql":
                                    results["injection"].append(f"SQL Pattern in {file}")
                except: continue

    # تنظيف النتائج
    smali_markers = ("invoke-", "iget-", "iput-", "move-result", "Landroid/", "Ljava/", ".method", ".line", ".locals")
    clean_secrets = [
        s for s in set(results["secrets"])
        if not any(marker in s for marker in smali_markers)
    ]

    results["secrets"] = clean_secrets[:10]
    results["endpoints"] = list(set(results["endpoints"]))[:10]
    return results
