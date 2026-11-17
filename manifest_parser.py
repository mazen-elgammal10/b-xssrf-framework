"""
Manifest Parser for B-XSSRF v7.
Comprehensive Android Manifest analysis and sensitive data extraction.
"""

from __future__ import annotations

import re

from androguard.core.apk import APK
from lxml import etree

from config_loader import get_risk_scoring_config, get_static_analysis_config
from logging_setup import get_logger, log_operation, silence_androguard_logs

logger = get_logger(__name__)

# Silence androguard at module level
silence_androguard_logs()


class BxssrfMobileParser:
    """Enhanced Android Manifest parser with comprehensive security analysis."""

    def __init__(self, apk_path: str) -> None:
        self.apk_path = apk_path
        self.config = get_static_analysis_config()
        self.risk_config = get_risk_scoring_config()

        # Silence androguard during APK loading
        silence_androguard_logs()
        self.apk = APK(apk_path)
        silence_androguard_logs()

        self.manifest = self.apk.get_android_manifest_xml()
        self._ns = "{http://schemas.android.com/apk/res/android}"

    # =========================
    # Attack Surface Analysis
    # =========================

    def get_attack_surface(self) -> list[list[str]]:
        """
        Comprehensive manifest attack surface analysis.

        Returns:
            List of [category, parameter, value, risk_level]
        """
        results: list[list[str]] = []

        with log_operation("manifest_analysis", apk_path=self.apk_path):
            app = self.manifest.find("application")
            if app is None:
                logger.warning("no_application_tag_in_manifest")
                return results

            # 1. Debuggable
            if self.config.manifest_checks.debuggable:
                results.extend(self._check_debuggable(app))

            # 2. AllowBackup
            if self.config.manifest_checks.allow_backup:
                results.extend(self._check_allow_backup(app))

            # 3. UsesCleartextTraffic
            if self.config.manifest_checks.uses_cleartext_traffic:
                results.extend(self._check_cleartext_traffic(app))

            # 4. Network Security Config
            if self.config.manifest_checks.network_security_config:
                results.extend(self._check_network_security_config(app))

            # 5. Exported Components
            if self.config.manifest_checks.exported_components:
                results.extend(self._check_exported_components())

            # 6. Backup Agent
            if self.config.manifest_checks.backup_agent:
                results.extend(self._check_backup_agent(app))

            # 7. Extract Native Libs
            if self.config.manifest_checks.extract_native_libs:
                results.extend(self._check_extract_native_libs(app))

            # 8. Dangerous Permissions
            if self.config.manifest_checks.dangerous_permissions:
                results.extend(self._check_dangerous_permissions())

            # 9. WebView Settings (from code analysis)
            if self.config.manifest_checks.webview_settings:
                results.extend(self._check_webview_settings())

            # 10. Custom TrustManager
            if self.config.manifest_checks.trust_manager_usage:
                results.extend(self._check_trust_manager_usage())

            logger.info("manifest_analysis_complete", findings=len(results))

        return results

    def _check_debuggable(self, app: etree._Element) -> list[list[str]]:
        """Check android:debuggable flag."""
        debuggable = app.get(f"{self._ns}debuggable")
        risk = self.risk_config.manifest_risks.get("debuggable", "CRITICAL")
        return [
            ["Manifest", "Debuggable", str(debuggable), risk if debuggable == "true" else "LOW"]
        ]

    def _check_allow_backup(self, app: etree._Element) -> list[list[str]]:
        """Check android:allowBackup flag."""
        backup = app.get(f"{self._ns}allowBackup")
        risk = self.risk_config.manifest_risks.get("allow_backup", "HIGH")
        return [
            ["Manifest", "AllowBackup", str(backup), risk if backup == "true" else "LOW"]
        ]

    def _check_cleartext_traffic(self, app: etree._Element) -> list[list[str]]:
        """Check android:usesCleartextTraffic flag."""
        cleartext = app.get(f"{self._ns}usesCleartextTraffic")
        risk = self.risk_config.manifest_risks.get("uses_cleartext_traffic", "HIGH")
        return [
            ["Manifest", "UsesCleartextTraffic", str(cleartext), risk if cleartext == "true" else "LOW"]
        ]

    def _check_network_security_config(self, app: etree._Element) -> list[list[str]]:
        """Check for Network Security Configuration."""
        net_sec_config = app.get(f"{self._ns}networkSecurityConfig")
        has_config = net_sec_config is not None
        risk = self.risk_config.manifest_risks.get("missing_network_security_config", "MEDIUM")
        return [
            ["Manifest", "NetworkSecurityConfig", str(net_sec_config) if has_config else "Missing",
             "LOW" if has_config else risk]
        ]

    def _check_exported_components(self) -> list[list[str]]:
        """Check for exported components without permissions."""
        results: list[list[str]] = []

        # Exported Activities
        for activity in self.manifest.findall(".//activity"):
            exported = activity.get(f"{self._ns}exported")
            permission = activity.get(f"{self._ns}permission")
            name = activity.get(f"{self._ns}name", "unknown")

            if exported == "true" and not permission:
                risk = self.risk_config.manifest_risks.get("exported_activity", "MEDIUM")
                results.append(["Manifest", f"Exported Activity: {name}", "true (no permission)", risk])

        # Exported Services
        for service in self.manifest.findall(".//service"):
            exported = service.get(f"{self._ns}exported")
            permission = service.get(f"{self._ns}permission")
            name = service.get(f"{self._ns}name", "unknown")

            if exported == "true" and not permission:
                risk = self.risk_config.manifest_risks.get("exported_service", "MEDIUM")
                results.append(["Manifest", f"Exported Service: {name}", "true (no permission)", risk])

        # Exported Receivers
        for receiver in self.manifest.findall(".//receiver"):
            exported = receiver.get(f"{self._ns}exported")
            permission = receiver.get(f"{self._ns}permission")
            name = receiver.get(f"{self._ns}name", "unknown")

            if exported == "true" and not permission:
                risk = self.risk_config.manifest_risks.get("exported_receiver", "MEDIUM")
                results.append(["Manifest", f"Exported Receiver: {name}", "true (no permission)", risk])

        # Exported Providers
        for provider in self.manifest.findall(".//provider"):
            exported = provider.get(f"{self._ns}exported")
            permission = provider.get(f"{self._ns}permission")
            name = provider.get(f"{self._ns}name", "unknown")

            if exported == "true" and not permission:
                risk = self.risk_config.manifest_risks.get("exported_provider", "HIGH")
                results.append(["Manifest", f"Exported Provider: {name}", "true (no permission)", risk])

        return results

    def _check_backup_agent(self, app: etree._Element) -> list[list[str]]:
        """Check for custom backup agent."""
        backup_agent = app.get(f"{self._ns}backupAgent")
        risk = self.risk_config.manifest_risks.get("backup_agent", "MEDIUM")
        return [
            ["Manifest", "BackupAgent", str(backup_agent) if backup_agent else "None",
             risk if backup_agent else "LOW"]
        ]

    def _check_extract_native_libs(self, app: etree._Element) -> list[list[str]]:
        """Check android:extractNativeLibs flag."""
        extract_native = app.get(f"{self._ns}extractNativeLibs")
        risk = self.risk_config.manifest_risks.get("extract_native_libs", "LOW")
        return [
            ["Manifest", "ExtractNativeLibs", str(extract_native) if extract_native else "true (default)",
             risk if extract_native == "true" else "LOW"]
        ]

    def _check_dangerous_permissions(self) -> list[list[str]]:
        """Check for dangerous permissions."""
        dangerous_perms = {
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.GET_ACCOUNTS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        }

        results: list[list[str]] = []
        perms = self.apk.get_permissions() or []

        for perm in perms:
            if perm in dangerous_perms:
                risk = self.risk_config.manifest_risks.get("dangerous_permission", "MEDIUM")
                results.append(["Manifest", f"Dangerous Permission: {perm}", "granted", risk])

        return results

    def _check_webview_settings(self) -> list[list[str]]:
        """Check for insecure WebView settings in code (basic scan)."""
        results: list[list[str]] = []

        # This is a basic check - deep scan in scraper.py does more thorough analysis
        try:
            silence_androguard_logs()
            for file in self.apk.get_files():
                if not file.endswith((".smali", ".kt", ".java")):
                    continue
                content = self.apk.get_file(file)
                text = content.decode("utf-8", errors="ignore")

                # Check for JavaScript enabled
                if "setJavaScriptEnabled" in text and "true" in text:
                    risk = self.risk_config.manifest_risks.get("webview_javascript_enabled", "MEDIUM")
                    results.append(["Code", "WebView JavaScript Enabled", "true", risk])

                # Check for DOM Storage enabled
                if "setDomStorageEnabled" in text and "true" in text:
                    risk = self.risk_config.manifest_risks.get("webview_dom_storage", "LOW")
                    results.append(["Code", "WebView DOM Storage Enabled", "true", risk])

                # Check for mixed content mode
                if "setMixedContentMode" in text and "MIXED_CONTENT_ALWAYS_ALLOW" in text:
                    risk = self.risk_config.manifest_risks.get("webview_mixed_content", "MEDIUM")
                    results.append(["Code", "WebView Mixed Content Allowed", "true", risk])

        except Exception as e:
            logger.debug("webview_settings_check_failed", error=str(e))

        return results

    def _check_trust_manager_usage(self) -> list[list[str]]:
        """Check for custom TrustManager implementations (SSL pinning bypass risk)."""
        results: list[list[str]] = []

        try:
            silence_androguard_logs()
            for file in self.apk.get_files():
                if not file.endswith((".smali", ".kt", ".java")):
                    continue
                content = self.apk.get_file(file)
                text = content.decode("utf-8", errors="ignore")

                # Look for custom TrustManager implementations
                if "X509TrustManager" in text or "TrustManager" in text:
                    if "checkServerTrusted" in text and ("return" in text or "empty" in text.lower()):
                        risk = self.risk_config.manifest_risks.get("custom_trust_manager", "HIGH")
                        results.append(["Code", "Custom TrustManager (Insecure)", "detected", risk])

        except Exception as e:
            logger.debug("trust_manager_check_failed", error=str(e))

        return results

    # =========================
    # Sensitive Data Extraction
    # =========================

    def extract_sensitive_data(self) -> dict[str, list[str]]:
        """
        Extract sensitive data from APK resources and code.

        Returns:
            Dict with categories: URLs, Emails, API Keys, Tokens
        """
        findings: dict[str, set[str]] = {
            "URLs": set(),
            "Emails": set(),
            "API Keys": set(),
            "Tokens": set(),
        }

        with log_operation("sensitive_data_extraction", apk_path=self.apk_path):
            # 1. Scan all files
            self._scan_all_files(findings)

            # 2. Scan Android resources (strings.xml, etc.)
            self._scan_android_resources(findings)

            # Clean and limit results
            max_results = self.config.deep_scan.max_results_per_category
            cleaned = {k: list(v)[:max_results] for k, v in findings.items()}

            total = sum(len(v) for v in cleaned.values())
            logger.info("sensitive_data_extraction_complete", total_findings=total)

        return cleaned

    def _scan_all_files(self, findings: dict[str, set[str]]) -> None:
        """Scan all relevant files in the APK."""
        extensions = tuple(self.config.deep_scan.extensions)
        exclude_patterns = self.config.deep_scan.exclude_patterns
        max_size = self.config.deep_scan.max_file_size

        try:
            silence_androguard_logs()
            for file in self.apk.get_files():
                # Check extension
                if not file.endswith(extensions):
                    continue

                # Check exclude patterns
                if any(self._match_pattern(file, pat) for pat in exclude_patterns):
                    continue

                try:
                    content = self.apk.get_file(file)
                    if len(content) > max_size:
                        continue
                    text = content.decode("utf-8", errors="ignore")
                    self._scan_text(text, findings)
                except Exception:
                    continue

        except Exception as e:
            logger.debug("file_scanning_failed", error=str(e))

    def _scan_android_resources(self, findings: dict[str, set[str]]) -> None:
        """Scan Android resources (strings.xml, etc.)."""
        try:
            silence_androguard_logs()
            res = self.apk.get_android_resources()
            strings = res.get_resolved_strings()
            for pkg in strings.values():
                for locale in pkg.values():
                    for s in locale.values():
                        self._scan_text(str(s), findings)
        except Exception as e:
            logger.debug("resource_scanning_failed", error=str(e))

    def _scan_text(self, text: str, findings: dict[str, set[str]]) -> None:
        """Scan text for sensitive patterns."""
        # Clean control characters
        text = re.sub(r"[\x00-\x1f]+", " ", text)

        patterns = self.config.sensitive_patterns

        # URLs
        if patterns.urls:
            urls = re.findall(r"https?://[^\s\"'<>]+", text)
            for u in urls:
                if "schemas.android.com" not in u:
                    findings["URLs"].add(u)

        # Emails
        if patterns.emails:
            findings["Emails"].update(
                re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)
            )

        # Google API Keys
        if patterns.api_keys:
            findings["API Keys"].update(
                re.findall(r"AIza[0-9A-Za-z\-_]{35}", text)
            )

        # AWS Access Keys
        if patterns.api_keys:
            findings["API Keys"].update(
                re.findall(r"AKIA[0-9A-Z]{16}", text)
            )

        # Generic API Keys
        if patterns.api_keys:
            for _, val in re.findall(
                r"(?i)(api[_-]?key)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9\-_]{8,})", text
            ):
                findings["API Keys"].add(val)

        # JWT Tokens
        if patterns.tokens:
            findings["Tokens"].update(
                re.findall(r"eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+", text)
            )

        # Bearer / Auth tokens
        if patterns.tokens:
            for _, val in re.findall(
                r"(?i)(token|auth|bearer)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9\-\._]{10,})", text
            ):
                findings["Tokens"].add(val)

        # Custom patterns
        for name, pattern in patterns.custom.items():
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        findings["API Keys"].add(str(match[-1]))
                    else:
                        findings["API Keys"].add(str(match))
            except Exception:
                continue

    def _match_pattern(self, filename: str, pattern: str) -> bool:
        """Simple glob pattern matching."""
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)
