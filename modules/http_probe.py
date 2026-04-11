"""
Enhanced HTTP Security Probe

Smart probing for sensitive files and misconfigurations with
content-based validation (not just status codes).
"""

import aiohttp
import asyncio
import re
from typing import Dict, Any, Optional, List

from .base import BaseModule


class HTTPProbeModule(BaseModule):
    name = "http_probe"
    description = "Enhanced HTTP security probing — detects exposed Git repos, .env files, debug endpoints with content validation."
    category = "Security Analysis"
    dependencies = []
    rate_limit_rpm = 60

    # Probes with content validators
    PROBES = [
        # Git exposure
        {
            "path": "/.git/HEAD",
            "name": "Git Repository",
            "severity": "critical",
            "validator": lambda text: text.startswith("ref: refs/"),
            "description": "Git repository is publicly accessible — full source code download possible",
        },
        {
            "path": "/.git/config",
            "name": "Git Config",
            "severity": "critical",
            "validator": lambda text: "[core]" in text or "[remote" in text,
            "description": "Git configuration exposed — may reveal remote repository URLs",
        },
        # SVN exposure
        {
            "path": "/.svn/entries",
            "name": "SVN Repository",
            "severity": "critical",
            "validator": lambda text: text.strip().split("\n")[0].isdigit() if text.strip() else False,
            "description": "SVN repository metadata accessible",
        },
        # Environment files
        {
            "path": "/.env",
            "name": "Environment File",
            "severity": "critical",
            "validator": lambda text: any(k in text for k in ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "DATABASE_URL"]),
            "description": "Environment file with credentials is publicly accessible",
        },
        {
            "path": "/.env.bak",
            "name": "Environment Backup",
            "severity": "critical",
            "validator": lambda text: any(k in text for k in ["DB_", "APP_", "SECRET", "KEY=", "PASSWORD"]),
            "description": "Backup environment file exposed",
        },
        {
            "path": "/.env.production",
            "name": "Production Env",
            "severity": "critical",
            "validator": lambda text: "=" in text and len(text) > 10,
            "description": "Production environment file exposed",
        },
        # macOS artifacts
        {
            "path": "/.DS_Store",
            "name": "macOS DS_Store",
            "severity": "medium",
            "validator": lambda text: "\x00\x00\x00\x01Bud1" in text or len(text) > 0,
            "description": "macOS .DS_Store file reveals directory structure",
            "binary": True,
        },
        # WordPress
        {
            "path": "/wp-config.php.bak",
            "name": "WordPress Config Backup",
            "severity": "critical",
            "validator": lambda text: "DB_NAME" in text or "DB_PASSWORD" in text,
            "description": "WordPress configuration backup with database credentials",
        },
        {
            "path": "/wp-config.php~",
            "name": "WordPress Config Editor Backup",
            "severity": "critical",
            "validator": lambda text: "DB_NAME" in text or "wp_" in text,
            "description": "Editor backup of WordPress configuration",
        },
        # Server status/info
        {
            "path": "/server-status",
            "name": "Apache Status",
            "severity": "high",
            "validator": lambda text: "Apache Server Status" in text or "Server Version" in text,
            "description": "Apache mod_status is publicly accessible — reveals server internals",
        },
        {
            "path": "/server-info",
            "name": "Apache Info",
            "severity": "high",
            "validator": lambda text: "Apache Server Information" in text,
            "description": "Apache mod_info is publicly accessible",
        },
        {
            "path": "/phpinfo.php",
            "name": "PHP Info",
            "severity": "high",
            "validator": lambda text: "PHP Version" in text or "phpinfo()" in text,
            "description": "phpinfo() page exposes detailed server configuration",
        },
        # Spring Boot Actuator
        {
            "path": "/actuator",
            "name": "Spring Actuator",
            "severity": "high",
            "validator": lambda text: '"_links"' in text and "actuator" in text,
            "description": "Spring Boot Actuator endpoints are publicly accessible",
        },
        {
            "path": "/actuator/env",
            "name": "Spring Actuator Env",
            "severity": "critical",
            "validator": lambda text: '"propertySources"' in text,
            "description": "Spring Boot environment variables exposed",
        },
        {
            "path": "/actuator/heapdump",
            "name": "Spring Heap Dump",
            "severity": "critical",
            "validator": lambda text: len(text) > 1000,
            "description": "Spring Boot heap dump downloadable — may contain credentials",
            "binary": True,
        },
        # .NET
        {
            "path": "/elmah.axd",
            "name": ".NET Error Log",
            "severity": "high",
            "validator": lambda text: "ELMAH" in text or "Error Log for" in text,
            "description": ".NET ELMAH error log is publicly accessible",
        },
        {
            "path": "/web.config",
            "name": ".NET Web Config",
            "severity": "critical",
            "validator": lambda text: "<configuration>" in text.lower(),
            "description": ".NET web.config exposed — may contain connection strings",
        },
        # Debug endpoints
        {
            "path": "/debug",
            "name": "Debug Endpoint",
            "severity": "high",
            "validator": lambda text: "debug" in text.lower() and len(text) > 100,
            "description": "Debug endpoint is publicly accessible",
        },
        {
            "path": "/trace",
            "name": "Trace Endpoint",
            "severity": "high",
            "validator": lambda text: '"traces"' in text or '"timestamp"' in text,
            "description": "Trace endpoint exposes request/response details",
        },
        # Backup files
        {
            "path": "/backup.sql",
            "name": "SQL Backup",
            "severity": "critical",
            "validator": lambda text: "CREATE TABLE" in text or "INSERT INTO" in text,
            "description": "SQL database backup is publicly downloadable",
        },
        {
            "path": "/database.sql",
            "name": "Database Dump",
            "severity": "critical",
            "validator": lambda text: "CREATE TABLE" in text or "INSERT INTO" in text,
            "description": "Database dump file is publicly accessible",
        },
        # API documentation
        {
            "path": "/swagger.json",
            "name": "Swagger API Spec",
            "severity": "medium",
            "validator": lambda text: '"swagger"' in text or '"openapi"' in text,
            "description": "API documentation (Swagger/OpenAPI) is publicly accessible",
        },
        {
            "path": "/openapi.json",
            "name": "OpenAPI Spec",
            "severity": "medium",
            "validator": lambda text: '"openapi"' in text,
            "description": "OpenAPI specification is publicly accessible",
        },
        # Misconfigured robots
        {
            "path": "/crossdomain.xml",
            "name": "Flash Crossdomain",
            "severity": "medium",
            "validator": lambda text: "allow-access-from" in text and 'domain="*"' in text,
            "description": "Flash crossdomain.xml allows access from any domain",
        },
        # Node.js
        {
            "path": "/package.json",
            "name": "Node.js Package",
            "severity": "medium",
            "validator": lambda text: '"dependencies"' in text or '"scripts"' in text,
            "description": "package.json exposed — reveals tech stack and dependencies",
        },
        # Composer (PHP)
        {
            "path": "/composer.json",
            "name": "Composer Package",
            "severity": "medium",
            "validator": lambda text: '"require"' in text and '"name"' in text,
            "description": "composer.json exposed — reveals PHP dependencies",
        },
    ]

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        results = {
            "target": target,
            "probes_run": len(self.PROBES),
            "findings": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }

        # Run probes concurrently in batches
        batch_size = 5
        for i in range(0, len(self.PROBES), batch_size):
            batch = self.PROBES[i:i + batch_size]
            tasks = [self._probe(session, target, probe) for probe in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, dict) and result.get("vulnerable"):
                    results["findings"].append(result)
                    sev = result.get("severity", "info")
                    if sev in results["summary"]:
                        results["summary"][sev] += 1

            await asyncio.sleep(0.2)

        # Risk assessment
        total_critical = results["summary"]["critical"]
        total_high = results["summary"]["high"]

        if total_critical > 0:
            results["risk_assessment"] = (
                f"CRITICAL: {total_critical} critical exposure(s) found. "
                "Immediate remediation required."
            )
            results["overall_severity"] = "critical"
        elif total_high > 0:
            results["risk_assessment"] = (
                f"HIGH: {total_high} high-severity exposure(s) found."
            )
            results["overall_severity"] = "high"
        elif results["findings"]:
            results["risk_assessment"] = f"Found {len(results['findings'])} exposure(s) — review recommended."
            results["overall_severity"] = "medium"
        else:
            results["risk_assessment"] = "No sensitive files or misconfigurations detected."
            results["overall_severity"] = "info"

        return results

    async def _probe(self, session: aiohttp.ClientSession, base_url: str, probe: dict) -> Dict[str, Any]:
        """Probe a single path with content validation."""
        from urllib.parse import urljoin
        url = urljoin(base_url, probe["path"])

        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with session.get(url, timeout=timeout, allow_redirects=False) as resp:
                if resp.status == 200:
                    is_binary = probe.get("binary", False)
                    if is_binary:
                        content = await resp.read()
                        text = content.decode("latin-1", errors="ignore")
                    else:
                        text = await resp.text(encoding="utf-8", errors="ignore")

                    # Content validation — not just status code check
                    try:
                        is_valid = probe["validator"](text)
                    except Exception:
                        is_valid = False

                    if is_valid:
                        return {
                            "vulnerable": True,
                            "path": probe["path"],
                            "name": probe["name"],
                            "severity": probe["severity"],
                            "description": probe["description"],
                            "url": url,
                            "status_code": resp.status,
                            "content_length": len(text),
                            "content_preview": text[:200] if not is_binary else f"[Binary: {len(text)} bytes]",
                        }
        except Exception:
            pass

        return {"vulnerable": False, "path": probe["path"]}
