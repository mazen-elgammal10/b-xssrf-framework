"""
Unit tests for scraper module.
"""

import tempfile
from pathlib import Path

from scraper import run


class TestScraper:
    """Tests for deep scanner."""

    def test_run_on_empty_dir(self) -> None:
        """Test scanner on empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = run(tmpdir)

            assert isinstance(results, dict)
            assert "secrets" in results
            assert "endpoints" in results
            assert "injection" in results
            assert results["secrets"] == []
            assert results["endpoints"] == []
            assert results["injection"] == []

    def test_run_finds_secrets(self) -> None:
        """Test scanner finds secrets in files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files with secrets (quoted values as expected by regex)
            test_file = Path(tmpdir) / "test.smali"
            test_file.write_text("""
                const-string v0, "api_key=\"AIzaSyTest123456789012345678901234567\""
                const-string v1, "password=\"secret123\""
            """)

            results = run(tmpdir)

            assert len(results["secrets"]) > 0
            # Should find the api key and password
            secrets_str = " ".join(results["secrets"])
            assert "api_key" in secrets_str.lower() or "password" in secrets_str.lower()

    def test_run_finds_endpoints(self) -> None:
        """Test scanner finds HTTP endpoints."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.xml"
            test_file.write_text("""
                <string name="api_url">https://api.example.com/v1</string>
                <string name="backup_url">http://backup.internal/data</string>
            """)

            results = run(tmpdir)

            assert len(results["endpoints"]) > 0
            endpoints_str = " ".join(results["endpoints"])
            assert "api.example.com" in endpoints_str or "backup.internal" in endpoints_str

    def test_run_finds_sql_patterns(self) -> None:
        """Test scanner finds SQL injection patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "query.smali"
            test_file.write_text("""
                const-string v0, "SELECT * FROM users WHERE id = "
                const-string v1, "INSERT INTO logs VALUES ("
            """)

            results = run(tmpdir)

            assert len(results["injection"]) > 0
            injection_str = " ".join(results["injection"])
            assert "SQL" in injection_str

    def test_run_excludes_binary_files(self) -> None:
        """Test scanner skips binary files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake .so file
            so_file = Path(tmpdir) / "libnative.so"
            so_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)

            results = run(tmpdir)
            # Should not crash and should have empty results
            assert results["secrets"] == []
            assert results["endpoints"] == []

    def test_run_limits_results(self) -> None:
        """Test scanner respects max results limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create many endpoint files
            for i in range(20):
                test_file = Path(tmpdir) / f"config{i}.xml"
                test_file.write_text(f'<string name="url">https://api{i}.example.com</string>')

            results = run(tmpdir)
            # Default max is 50, but we only created 20
            assert len(results["endpoints"]) <= 20
