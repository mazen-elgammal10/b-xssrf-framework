"""
Unit tests for config_loader module.
"""

import tempfile
from pathlib import Path

import yaml

from config_loader import (
    BxssrfConfig,
    GeneralConfig,
    PayloadsConfig,
    StaticAnalysisConfig,
    get_config,
    get_general_config,
    get_payloads_config,
    get_static_analysis_config,
    reload_config,
)


class TestConfigModels:
    """Tests for configuration Pydantic models."""

    def test_general_config_defaults(self) -> None:
        """Test GeneralConfig default values."""
        config = GeneralConfig()
        assert config.log_level == "INFO"
        assert config.output_dir == "./output"
        assert config.max_concurrent == 4
        assert config.default_timeout == 30

    def test_general_config_custom(self) -> None:
        """Test GeneralConfig with custom values."""
        config = GeneralConfig(log_level="DEBUG", output_dir="/tmp/test", max_concurrent=8)
        assert config.log_level == "DEBUG"
        assert config.output_dir == "/tmp/test"
        assert config.max_concurrent == 8

    def test_static_analysis_config_defaults(self) -> None:
        """Test StaticAnalysisConfig defaults."""
        config = StaticAnalysisConfig()
        assert config.manifest_checks.debuggable is True
        assert config.manifest_checks.allow_backup is True
        assert config.deep_scan.enabled is True
        assert ".smali" in config.deep_scan.extensions

    def test_payloads_config_defaults(self) -> None:
        """Test PayloadsConfig model defaults (empty lists)."""
        config = PayloadsConfig()
        assert isinstance(config.ssrf, list)
        assert config.ssrf == []  # Model defaults are empty
        assert config.path_traversal == []
        assert config.open_redirect == []
        assert config.xxe == []
        assert config.webview_abuse == []
        assert config.intent_abuse == []

    def test_payloads_config_from_yaml(self) -> None:
        """Test PayloadsConfig loaded from YAML has values."""
        config = reload_config()  # Load default config.yaml
        assert len(config.payloads.ssrf) > 0
        assert "http://169.254.169.254/latest/meta-data/" in config.payloads.ssrf
        assert len(config.payloads.xxe) > 0

    def test_full_config_creation(self) -> None:
        """Test full BxssrfConfig creation."""
        config = BxssrfConfig()
        assert isinstance(config.general, GeneralConfig)
        assert isinstance(config.static_analysis, StaticAnalysisConfig)
        assert isinstance(config.payloads, PayloadsConfig)


class TestConfigLoading:
    """Tests for configuration loading."""

    def test_load_config_from_yaml(self) -> None:
        """Test loading config from YAML file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_data = {
                "general": {
                    "log_level": "DEBUG",
                    "output_dir": "/custom/output",
                },
                "static_analysis": {
                    "manifest_checks": {
                        "debuggable": False,
                    },
                    "deep_scan": {
                        "max_results_per_category": 100,
                    },
                },
            }
            config_path.write_text(yaml.dump(config_data))

            # Load with explicit path (use reload_config to bypass singleton)
            config = reload_config(config_path)

            assert config.general.log_level == "DEBUG"
            assert config.general.output_dir == "/custom/output"
            assert config.static_analysis.manifest_checks.debuggable is False
            assert config.static_analysis.deep_scan.max_results_per_category == 100
            # Other values should be defaults
            assert config.static_analysis.manifest_checks.allow_backup is True

    def test_load_config_merges_with_defaults(self) -> None:
        """Test that partial config merges with defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_data = {
                "general": {
                    "log_level": "WARNING",
                },
            }
            config_path.write_text(yaml.dump(config_data))

            config = reload_config(config_path)

            assert config.general.log_level == "WARNING"
            # Other general settings should be defaults
            assert config.general.output_dir == "./output"
            assert config.general.max_concurrent == 4

    def test_load_config_nonexistent_file(self) -> None:
        """Test loading with nonexistent file uses defaults."""
        config = reload_config("/nonexistent/path/config.yaml")

        # Should return defaults
        assert config.general.log_level == "INFO"
        assert config.static_analysis.manifest_checks.debuggable is True

    def test_config_singleton(self) -> None:
        """Test that get_config returns same instance."""
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2

    def test_reload_config(self) -> None:
        """Test config reload."""
        from config_loader import _config, reload_config

        # Set a config
        config1 = get_config()
        assert _config is not None

        # Reload should reset
        config2 = reload_config()
        assert config2 is not config1  # New instance


class TestConfigAccessors:
    """Tests for config accessor functions."""

    def test_get_general_config(self) -> None:
        """Test get_general_config accessor."""
        config = get_general_config()
        assert isinstance(config, GeneralConfig)

    def test_get_static_analysis_config(self) -> None:
        """Test get_static_analysis_config accessor."""
        config = get_static_analysis_config()
        assert isinstance(config, StaticAnalysisConfig)

    def test_get_payloads_config(self) -> None:
        """Test get_payloads_config accessor."""
        config = get_payloads_config()
        assert isinstance(config, PayloadsConfig)
