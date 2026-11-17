"""
Unit tests for payload_factory module.
"""

from payload_factory import PayloadGenerator, generate_payloads


class TestPayloadFactory:
    """Tests for payload generation."""

    def test_generate_payloads_basic(self) -> None:
        """Test basic payload generation."""
        payloads = generate_payloads("https://example.com/api")

        assert isinstance(payloads, list)
        assert len(payloads) > 0
        # Check all payloads contain the base URL
        for p in payloads:
            assert "example.com/api" in p

    def test_generate_payloads_ssrf(self) -> None:
        """Test SSRF payloads are generated."""
        payloads = generate_payloads("https://example.com/api", categories=["ssrf"])

        # Should contain SSRF payloads
        ssrf_indicators = ["169.254.169.254", "127.0.0.1", "localhost", "10.0.2.2"]
        found = any(any(ind in p for ind in ssrf_indicators) for p in payloads)
        assert found, "No SSRF payloads found"

    def test_generate_payloads_path_traversal(self) -> None:
        """Test path traversal payloads."""
        payloads = generate_payloads("https://example.com/api", categories=["path_traversal"])

        traversal_indicators = ["../", "..\\"]
        found = any(any(ind in p for ind in traversal_indicators) for p in payloads)
        assert found, "No path traversal payloads found"

    def test_generate_payloads_open_redirect(self) -> None:
        """Test open redirect payloads."""
        payloads = generate_payloads("https://example.com/api", categories=["open_redirect"])

        redirect_indicators = ["evil.com", "attacker.com"]
        found = any(any(ind in p for ind in redirect_indicators) for p in payloads)
        assert found, "No open redirect payloads found"

    def test_generate_payloads_webview_abuse(self) -> None:
        """Test WebView abuse payloads."""
        payloads = generate_payloads("https://example.com/api", categories=["webview_abuse"])

        webview_indicators = ["javascript:"]
        found = any(any(ind in p for ind in webview_indicators) for p in payloads)
        assert found, "No WebView abuse payloads found"

    def test_generate_payloads_intent_abuse(self) -> None:
        """Test Intent abuse payloads."""
        payloads = generate_payloads("https://example.com/api", categories=["intent_abuse"])

        intent_indicators = ["intent://"]
        found = any(any(ind in p for ind in intent_indicators) for p in payloads)
        assert found, "No Intent abuse payloads found"

    def test_generate_payloads_xxe(self) -> None:
        """Test XXE payloads."""
        payloads = generate_payloads("https://example.com/api", categories=["xxe"])

        # XXE payloads are URL-encoded
        xxe_indicators = ["%3C%21DOCTYPE", "%3C%21ENTITY"]
        found = any(any(ind in p for ind in xxe_indicators) for p in payloads)
        assert found, "No XXE payloads found"

    def test_generate_payloads_deduplication(self) -> None:
        """Test that payloads are deduplicated."""
        # Use a URL that might generate duplicates
        payloads = generate_payloads("https://example.com/api")
        unique_payloads = list(dict.fromkeys(payloads))
        assert len(payloads) == len(unique_payloads), "Payloads contain duplicates"

    def test_payload_generator_class(self) -> None:
        """Test PayloadGenerator class."""
        gen = PayloadGenerator()
        payloads = gen.generate_for_endpoint("https://example.com/api")

        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_payload_generator_classify_endpoint(self) -> None:
        """Test endpoint classification."""
        gen = PayloadGenerator()
        result = gen.classify_endpoint("https://example.com/api")

        assert isinstance(result, dict)
        assert "type" in result
        assert "confidence" in result
