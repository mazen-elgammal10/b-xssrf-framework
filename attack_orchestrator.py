# attack_orchestrator.py

from payload_factory import generate_payloads
from executor import send_payload_to_adb
from logcat_monitor import collect_logs
from result_analyzer import analyze_logcat


def decide_attacks(results):
    attacks = []

    for r in results:
        category, param, value, risk = r

        if param == "Deep Links" and value != "None":
            attacks.append(("deeplink", value))

        if param == "AllowBackup" and value == "true":
            attacks.append(("backup", None))

        if param == "Debuggable" and value == "true":
            attacks.append(("jdwp", None))

    return attacks


def run_attacks(results):
    findings = []

    attacks = decide_attacks(results)

    for attack_type, data in attacks:

        if attack_type == "deeplink":
            for link in data:
                payloads = generate_payloads(link)

                for p in payloads:
                    ok, _ = send_payload_to_adb(p)

                    if not ok:
                        continue

                    logs = collect_logs()
                    analysis = analyze_logcat(logs)

                    if analysis:
                        findings.append({
                            "type": "deeplink",
                            "payload": p,
                            "evidence": analysis
                        })

        elif attack_type == "backup":
            findings.append({
                "type": "backup",
                "evidence": "App allows backup → possible data extraction"
            })

        elif attack_type == "jdwp":
            findings.append({
                "type": "jdwp",
                "evidence": "App is debuggable → code execution possible"
            })

    return findings
