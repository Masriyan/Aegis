"""
Reverse IP Lookup & Shared Hosting Detection

Given a target's IP, discovers all other domains hosted on the same server.
Reveals co-tenants, lateral targets, and shared hosting risks.
"""

import aiohttp
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from .base import BaseModule


class ReverseIPModule(BaseModule):
    name = "reverse_ip"
    description = "Finds all domains hosted on the same IP — reveals shared hosting, co-tenants, and lateral targets."
    category = "Discovery & Fingerprinting"
    dependencies = []
    rate_limit_rpm = 30

    HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/"
    VIEWDNS_URL = "https://api.viewdns.info/reverseip/"

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        import socket
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {"error": f"Could not resolve {domain}", "domains": [], "ip": None}

        results = {
            "ip": ip,
            "target_domain": domain,
            "domains": [],
            "total_found": 0,
            "shared_hosting": False,
            "risk_assessment": "Low",
            "hosting_provider": None,
        }

        # Primary source: HackerTarget (free, no API key)
        domains = await self._hackertarget_lookup(session, ip)

        if domains:
            # Filter out obvious false positives and the target itself
            cleaned = []
            for d in domains:
                d = d.strip().lower()
                if d and d != domain.lower() and "." in d and len(d) > 3:
                    cleaned.append(d)
            results["domains"] = list(set(cleaned))[:100]  # Dedupe and cap

        results["total_found"] = len(results["domains"])
        results["shared_hosting"] = results["total_found"] > 1

        # Risk assessment
        if results["total_found"] > 20:
            results["risk_assessment"] = "High — Shared hosting with many co-tenants increases lateral attack risk"
        elif results["total_found"] > 5:
            results["risk_assessment"] = "Medium — Multiple domains on same IP suggest shared hosting"
        elif results["total_found"] > 0:
            results["risk_assessment"] = "Low — Few co-tenant domains"
        else:
            results["risk_assessment"] = "Info — Appears to be dedicated hosting"

        return results

    async def _hackertarget_lookup(self, session: aiohttp.ClientSession, ip: str) -> List[str]:
        """Query HackerTarget free reverse IP API."""
        try:
            resp = await self.async_fetch(
                f"{self.HACKERTARGET_URL}?q={ip}",
                session,
                timeout=aiohttp.ClientTimeout(total=15),
            )
            if resp and resp.status == 200:
                text = await resp.text()
                resp.close()
                # HackerTarget returns one domain per line
                if "error" not in text.lower() and "api count" not in text.lower():
                    return [line.strip() for line in text.strip().split("\n") if line.strip()]
        except Exception:
            pass
        return []
