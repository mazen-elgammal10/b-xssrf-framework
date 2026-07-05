# result_analyzer.py

def analyze_logcat(logs):
    findings = []

    logs_lower = logs.lower()

    # 💥 crashes
    if "exception" in logs_lower or "fatal" in logs_lower:
        findings.append("App Crash Detected")

    # 📂 file access
    if "file" in logs_lower and "denied" in logs_lower:
        findings.append("File Access Attempt")

    # 🌐 webview / SSRF
    if "webview" in logs_lower and "http" in logs_lower:
        findings.append("WebView Loading External URL")

    # 🔥 intent issues
    if "intent" in logs_lower and "error" in logs_lower:
        findings.append("Intent Handling Issue")

    return findings
