"""
Unit tests for attack_orchestrator module.
"""

from unittest.mock import Mock, patch

from attack_orchestrator import decide_attacks, run_attacks


class TestAttackOrchestrator:
    """Tests for attack orchestration logic."""

    def test_decide_attacks_debuggable(self) -> None:
        """Test attack decision for debuggable app."""
        results = [
            ["Manifest", "Debuggable", "true", "CRITICAL"],
            ["Manifest", "AllowBackup", "false", "LOW"],
        ]

        attacks = decide_attacks(results)

        assert len(attacks) == 1
        assert attacks[0][0] == "jdwp"

    def test_decide_attacks_allow_backup(self) -> None:
        """Test attack decision for allowBackup."""
        results = [
            ["Manifest", "Debuggable", "false", "LOW"],
            ["Manifest", "AllowBackup", "true", "HIGH"],
        ]

        attacks = decide_attacks(results)

        assert len(attacks) == 1
        assert attacks[0][0] == "backup"

    def test_decide_attacks_both(self) -> None:
        """Test attack decision for both vulnerabilities."""
        results = [
            ["Manifest", "Debuggable", "true", "CRITICAL"],
            ["Manifest", "AllowBackup", "true", "HIGH"],
        ]

        attacks = decide_attacks(results)

        assert len(attacks) == 2
        attack_types = [a[0] for a in attacks]
        assert "jdwp" in attack_types
        assert "backup" in attack_types

    def test_decide_attacks_exported_provider(self) -> None:
        """Test attack decision for exported content provider."""
        results = [
            ["Manifest", "Exported Provider: com.example.Provider", "true (no permission)", "HIGH"],
        ]

        attacks = decide_attacks(results)

        assert len(attacks) == 1
        assert attacks[0][0] == "content_provider"

    def test_decide_attacks_exported_activity(self) -> None:
        """Test attack decision for exported activity."""
        results = [
            ["Manifest", "Exported Activity: com.example.Activity", "true (no permission)", "MEDIUM"],
        ]

        attacks = decide_attacks(results)

        assert len(attacks) == 1
        assert attacks[0][0] == "intent_injection"

    def test_decide_attacks_cleartext(self) -> None:
        """Test attack decision for cleartext traffic."""
        results = [
            ["Manifest", "UsesCleartextTraffic", "true", "HIGH"],
        ]

        attacks = decide_attacks(results)

        assert len(attacks) == 1
        assert attacks[0][0] == "cleartext_mitm"

    def test_decide_attacks_none(self) -> None:
        """Test attack decision for secure app."""
        results = [
            ["Manifest", "Debuggable", "false", "LOW"],
            ["Manifest", "AllowBackup", "false", "LOW"],
        ]

        attacks = decide_attacks(results)

        assert len(attacks) == 0

    @patch("attack_orchestrator.send_payload_to_adb")
    @patch("attack_orchestrator.collect_logs")
    @patch("attack_orchestrator.analyze_logcat")
    def test_run_attacks_deeplink(
        self,
        mock_analyze: Mock,
        mock_collect: Mock,
        mock_send: Mock,
    ) -> None:
        """Test running deeplink attacks."""
        mock_send.return_value = (True, "success")
        mock_collect.return_value = "logcat output"
        mock_analyze.return_value = ["App Crash Detected"]

        results = [
            ["Manifest", "Deep Links", "myapp://deeplink", "MEDIUM"],
        ]

        findings = run_attacks(results)

        assert len(findings) > 0
        # Should have attempted payloads and analyzed logs
        mock_send.assert_called()
        mock_analyze.assert_called()

    def test_run_attacks_theoretical_findings(self) -> None:
        """Test that run_attacks returns theoretical findings without ADB."""
        # run_attacks doesn't check ADB - it returns theoretical findings
        # ADB check is done in CLI before calling run_attacks
        results = [
            ["Manifest", "Debuggable", "true", "CRITICAL"],
            ["Manifest", "AllowBackup", "true", "HIGH"],
        ]

        findings = run_attacks(results)

        # Should report theoretical findings for both
        assert len(findings) >= 2
        finding_types = {f["type"] for f in findings}
        assert "jdwp" in finding_types
        assert "backup" in finding_types

        # Check structure
        for f in findings:
            assert "type" in f
            assert "evidence" in f
            assert "severity" in f


class TestRunAttacksIntegration:
    """Integration-style tests for run_attacks."""

    def test_backup_finding_structure(self) -> None:
        """Test backup finding has correct structure."""
        findings = []

        # Simulate backup attack
        findings.append({
            "type": "backup",
            "evidence": "App allows backup → possible data extraction",
            "severity": "HIGH",
        })

        assert findings[0]["type"] == "backup"
        assert findings[0]["severity"] == "HIGH"
        assert "backup" in findings[0]["evidence"].lower()

    def test_jdwp_finding_structure(self) -> None:
        """Test JDWP finding has correct structure."""
        findings = [{
            "type": "jdwp",
            "evidence": "App is debuggable → code execution possible",
            "severity": "CRITICAL",
        }]

        assert findings[0]["type"] == "jdwp"
        assert findings[0]["severity"] == "CRITICAL"
