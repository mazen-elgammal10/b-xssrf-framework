"""
Configuration loader for B-XSSRF v7.
Loads config from config.yaml and optional config.local.yaml override.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ============================
# Pydantic Models for Config Validation
# ============================

class GeneralConfig(BaseModel):
    log_level: str = "INFO"
    output_dir: str = "./output"
    max_concurrent: int = 4
    default_timeout: int = 30


class ManifestChecksConfig(BaseModel):
    debuggable: bool = True
    allow_backup: bool = True
    uses_cleartext_traffic: bool = True
    network_security_config: bool = True
    exported_components: bool = True
    backup_agent: bool = True
    extract_native_libs: bool = True
    dangerous_permissions: bool = True
    webview_settings: bool = True
    trust_manager_usage: bool = True


class SensitivePatternsConfig(BaseModel):
    urls: bool = True
    emails: bool = True
    api_keys: bool = True
    tokens: bool = True
    custom: dict[str, str] = Field(default_factory=dict)


class DeepScanConfig(BaseModel):
    enabled: bool = True
    extensions: list[str] = Field(default_factory=lambda: [".xml", ".txt", ".json", ".html", ".js", ".smali", ".kt", ".java"])
    max_file_size: int = 1048576
    exclude_patterns: list[str] = Field(default_factory=lambda: ["*.png", "*.jpg", "*.jpeg", "*.gif", "*.so", "*.dex", "*.odex"])
    max_results_per_category: int = 50


class StaticAnalysisConfig(BaseModel):
    manifest_checks: ManifestChecksConfig = Field(default_factory=ManifestChecksConfig)
    sensitive_patterns: SensitivePatternsConfig = Field(default_factory=SensitivePatternsConfig)
    deep_scan: DeepScanConfig = Field(default_factory=DeepScanConfig)


class DynamicAnalysisConfig(BaseModel):
    enabled: bool = True
    script_path: str = "frida_hook.js"
    additional_scripts: list[str] = Field(default_factory=list)
    spawn_mode: bool = True
    hook_categories: list[str] = Field(default_factory=lambda: ["network", "storage", "ipc", "auth", "anti"])
    event_collection: dict[str, Any] = Field(default_factory=lambda: {
        "max_events": 1000,
        "flush_interval": 5,
        "include_stack_traces": True,
    })


class AdbConfig(BaseModel):
    enabled: bool = True
    timeout: int = 10
    jdwp_tools: list[str] = Field(default_factory=lambda: ["jdwp-shellifier", "jdwp-control"])


class DeeplinkConfig(BaseModel):
    enabled: bool = True
    payload_categories: list[str] = Field(default_factory=lambda: [
        "ssrf", "path_traversal", "open_redirect", "webview_abuse", "intent_abuse", "xxe", "deserialization"
    ])
    max_payloads_per_endpoint: int = 20


class BackupConfig(BaseModel):
    enabled: bool = True
    abe_jar_path: str = ""
    auto_extract: bool = True
    analyze_content: bool = True


class ContentProviderConfig(BaseModel):
    enabled: bool = True
    test_sql_injection: bool = True
    test_path_traversal: bool = True
    test_grant_uri_permission: bool = True


class ExploitationConfig(BaseModel):
    adb: AdbConfig = Field(default_factory=AdbConfig)
    deeplink: DeeplinkConfig = Field(default_factory=DeeplinkConfig)
    backup: BackupConfig = Field(default_factory=BackupConfig)
    content_provider: ContentProviderConfig = Field(default_factory=ContentProviderConfig)


class PayloadsConfig(BaseModel):
    ssrf: list[str] = Field(default_factory=list)
    path_traversal: list[str] = Field(default_factory=list)
    open_redirect: list[str] = Field(default_factory=list)
    xxe: list[str] = Field(default_factory=list)
    webview_abuse: list[str] = Field(default_factory=list)
    intent_abuse: list[str] = Field(default_factory=list)


class PortScanConfig(BaseModel):
    enabled: bool = True
    ports: str = "1-65535"
    scan_type: str = "syn"
    service_detection: bool = True
    os_detection: bool = False
    timing: int = 3


class VulnerabilityScanConfig(BaseModel):
    enabled: bool = False
    templates_path: str = ""
    severity: list[str] = Field(default_factory=lambda: ["critical", "high", "medium"])
    tags: list[str] = Field(default_factory=lambda: ["cve", "misconfiguration", "exposure"])


class SubdomainEnumConfig(BaseModel):
    enabled: bool = False
    sources: list[str] = Field(default_factory=lambda: ["crtsh", "virustotal", "securitytrails"])
    recursive: bool = False


class SslAnalysisConfig(BaseModel):
    enabled: bool = True
    check_cert_transparency: bool = True
    check_weak_ciphers: bool = True
    check_protocols: bool = True


class InfrastructureConfig(BaseModel):
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    vulnerability_scan: VulnerabilityScanConfig = Field(default_factory=VulnerabilityScanConfig)
    subdomain_enum: SubdomainEnumConfig = Field(default_factory=SubdomainEnumConfig)
    ssl_analysis: SslAnalysisConfig = Field(default_factory=SslAnalysisConfig)


class ReportingConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["console", "txt", "json", "sarif"])
    sections: list[str] = Field(default_factory=lambda: [
        "manifest_risks", "secrets_manifest", "deep_scan",
        "generated_payloads", "live_exploitation", "network_infra", "recommendations"
    ])
    sarif: dict[str, Any] = Field(default_factory=lambda: {
        "version": "2.1.0",
        "tool_name": "B-XSSRF",
        "tool_version": "7.0.0",
    })
    auto_save: bool = False
    filename_template: str = "bxssrf_report_{timestamp}.{ext}"


class RiskScoringConfig(BaseModel):
    manifest_risks: dict[str, str] = Field(default_factory=dict)
    sensitive_data: dict[str, str] = Field(default_factory=dict)


class PluginsConfig(BaseModel):
    enabled: bool = False
    plugin_dirs: list[str] = Field(default_factory=lambda: ["./plugins"])
    auto_load: bool = True
    configs: dict[str, Any] = Field(default_factory=dict)


class BxssrfConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    static_analysis: StaticAnalysisConfig = Field(default_factory=StaticAnalysisConfig)
    dynamic_analysis: DynamicAnalysisConfig = Field(default_factory=DynamicAnalysisConfig)
    exploitation: ExploitationConfig = Field(default_factory=ExploitationConfig)
    payloads: PayloadsConfig = Field(default_factory=PayloadsConfig)
    infrastructure: InfrastructureConfig = Field(default_factory=InfrastructureConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)


# ============================
# Settings Class with Env Override Support
# ============================

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BXSSRF_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    static_analysis: StaticAnalysisConfig = Field(default_factory=StaticAnalysisConfig)
    dynamic_analysis: DynamicAnalysisConfig = Field(default_factory=DynamicAnalysisConfig)
    exploitation: ExploitationConfig = Field(default_factory=ExploitationConfig)
    payloads: PayloadsConfig = Field(default_factory=PayloadsConfig)
    infrastructure: InfrastructureConfig = Field(default_factory=InfrastructureConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)


# ============================
# Config Loader
# ============================

_config: BxssrfConfig | None = None


def load_config(config_path: str | Path | None = None) -> BxssrfConfig:
    """
    Load configuration from YAML files.

    Priority (highest to lowest):
    1. Environment variables (BXSSRF_*)
    2. config.local.yaml (local overrides, gitignored)
    3. config.yaml (default config)
    4. Pydantic defaults
    """
    global _config

    if _config is not None:
        return _config

    # Start with defaults
    config_dict: dict[str, Any] = {}

    # Load config.yaml
    default_paths = [
        Path("config.yaml"),
        Path(__file__).parent / "config.yaml",
    ]

    for path in default_paths:
        if path.exists():
            with open(path, encoding="utf-8") as f:
                config_dict = yaml.safe_load(f) or {}
            break

    # Load config.local.yaml (overrides)
    local_paths = [
        Path("config.local.yaml"),
        Path(__file__).parent / "config.local.yaml",
    ]

    for path in local_paths:
        if path.exists():
            with open(path, encoding="utf-8") as f:
                local_config = yaml.safe_load(f) or {}
            config_dict = _deep_merge(config_dict, local_config)
            break

    # Use explicit config_path if provided (highest priority among files)
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path, encoding="utf-8") as f:
                explicit_config = yaml.safe_load(f) or {}
            config_dict = _deep_merge(config_dict, explicit_config)

    # Validate and create config object
    # Use Settings for env var override support, but manually construct nested models from YAML
    settings = Settings(**config_dict)

    # Manually create nested configs from merged YAML to ensure YAML values take precedence
    _config = BxssrfConfig(
        general=GeneralConfig(**config_dict.get("general", {})),
        static_analysis=StaticAnalysisConfig(**config_dict.get("static_analysis", {})),
        dynamic_analysis=DynamicAnalysisConfig(**config_dict.get("dynamic_analysis", {})),
        exploitation=ExploitationConfig(**config_dict.get("exploitation", {})),
        payloads=PayloadsConfig(**config_dict.get("payloads", {})),
        infrastructure=InfrastructureConfig(**config_dict.get("infrastructure", {})),
        reporting=ReportingConfig(**config_dict.get("reporting", {})),
        risk_scoring=RiskScoringConfig(**config_dict.get("risk_scoring", {})),
        plugins=PluginsConfig(**config_dict.get("plugins", {})),
    )

    return _config


def get_config() -> BxssrfConfig:
    """Get the loaded config (loads if not already loaded)."""
    if _config is None:
        return load_config()
    return _config


def reload_config(config_path: str | Path | None = None) -> BxssrfConfig:
    """Force reload configuration."""
    global _config
    _config = None
    return load_config(config_path)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ============================
# Convenience Accessors
# ============================

def get_general_config() -> GeneralConfig:
    return get_config().general


def get_static_analysis_config() -> StaticAnalysisConfig:
    return get_config().static_analysis


def get_dynamic_analysis_config() -> DynamicAnalysisConfig:
    return get_config().dynamic_analysis


def get_exploitation_config() -> ExploitationConfig:
    return get_config().exploitation


def get_payloads_config() -> PayloadsConfig:
    return get_config().payloads


def get_infrastructure_config() -> InfrastructureConfig:
    return get_config().infrastructure


def get_reporting_config() -> ReportingConfig:
    return get_config().reporting


def get_risk_scoring_config() -> RiskScoringConfig:
    return get_config().risk_scoring


def get_plugins_config() -> PluginsConfig:
    return get_config().plugins
