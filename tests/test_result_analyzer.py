"""
Unit tests for result_analyzer module.
"""

from result_analyzer import analyze_logcat, analyze_logcat_structured


class TestResultAnalyzer:
    """Tests for logcat analysis."""

    def test_analyze_empty_logs(self) -> None:
        """Test analysis of empty logs."""
        findings = analyze_logcat("")
        assert findings == []

        findings = analyze_logcat("   \n\n  ")
        assert findings == []

    def test_analyze_crash_detection(self) -> None:
        """Test crash detection in logs."""
        logs = """
        12-25 10:00:00.000  1234  1234 E AndroidRuntime: FATAL EXCEPTION: main
        12-25 10:00:00.000  1234  1234 E AndroidRuntime: java.lang.NullPointerException
        """

        findings = analyze_logcat(logs)

        assert len(findings) > 0
        crash_findings = [f for f in findings if "Crash" in f or "Exception" in f]
        assert len(crash_findings) > 0

    def test_analyze_anr_detection(self) -> None:
        """Test ANR detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 E ActivityManager: ANR in com.example.app
        """

        findings = analyze_logcat(logs)

        anr_findings = [f for f in findings if "ANR" in f or "Not Responding" in f]
        assert len(anr_findings) > 0

    def test_analyze_file_access_violation(self) -> None:
        """Test file access violation detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 E Database: open failed: EACCES (Permission denied)
        """

        findings = analyze_logcat(logs)

        file_findings = [f for f in findings if "File Access" in f or "Permission" in f]
        assert len(file_findings) > 0

    def test_analyze_webview_activity(self) -> None:
        """Test WebView activity detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 I WebView: loadUrl: http://example.com
        """

        findings = analyze_logcat(logs)

        webview_findings = [f for f in findings if "WebView" in f]
        assert len(webview_findings) > 0

    def test_analyze_intent_issues(self) -> None:
        """Test Intent handling issue detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 E ActivityManager: ActivityNotFoundException
        """

        findings = analyze_logcat(logs)

        intent_findings = [f for f in findings if "Intent" in f]
        assert len(intent_findings) > 0

    def test_analyze_sql_errors(self) -> None:
        """Test SQL error detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 E SQLiteLog: (1) near "SELECT": syntax error
        """

        findings = analyze_logcat(logs)

        sql_findings = [f for f in findings if "SQL" in f]
        assert len(sql_findings) > 0

    def test_analyze_network_ssl_issues(self) -> None:
        """Test network/SSL issue detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 E HttpClient: javax.net.ssl.SSLHandshakeException
        """

        findings = analyze_logcat(logs)

        network_findings = [f for f in findings if "Network" in f or "SSL" in f]
        assert len(network_findings) > 0

    def test_analyze_jdwp_activity(self) -> None:
        """Test JDWP/debug activity detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 I JDWP: Debug port 8700 opened
        """

        findings = analyze_logcat(logs)

        jdwp_findings = [f for f in findings if "JDWP" in f or "Debug" in f]
        assert len(jdwp_findings) > 0

    def test_analyze_exploitation_indicators(self) -> None:
        """Test exploitation success indicators."""
        logs = """
        12-25 10:00:00.000  1234  1234 I Shell: uid=0(root) gid=0(root)
        """

        findings = analyze_logcat(logs)

        exploit_findings = [f for f in findings if "Exploitation" in f or "Command Execution" in f or "Root" in f]
        assert len(exploit_findings) > 0

    def test_analyze_ssrf_indicators(self) -> None:
        """Test SSRF indicators."""
        logs = """
        12-25 10:00:00.000  1234  1234 I Network: Connecting to 169.254.169.254
        """

        findings = analyze_logcat(logs)

        ssrf_findings = [f for f in findings if "SSRF" in f]
        assert len(ssrf_findings) > 0

    def test_analyze_path_traversal(self) -> None:
        """Test path traversal detection."""
        logs = """
        12-25 10:00:00.000  1234  1234 I File: Opening ../../../etc/passwd
        """

        findings = analyze_logcat(logs)

        path_findings = [f for f in findings if "Path Traversal" in f]
        assert len(path_findings) > 0

    def test_analyze_logcat_structured(self) -> None:
        """Test structured analysis output."""
        logs = """
        12-25 10:00:00.000  1234  1234 E AndroidRuntime: FATAL EXCEPTION
        """

        result = analyze_logcat_structured(logs)

        assert isinstance(result, dict)
        assert "findings" in result
        assert "stats" in result
        assert "total_findings" in result
        assert "timestamp" in result
        assert result["total_findings"] > 0
        assert result["log_lines"] > 0
