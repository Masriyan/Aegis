"""
SPF Record Flattening & Deep Analysis

Recursively walks SPF include chains to:
- Count total DNS lookups (SPF has a 10-lookup hard limit)
- Detect overly permissive policies (+all)
- Identify all authorized senders
- Flag broken SPF (exceeds lookup limit)
"""

import aiohttp
import asyncio
import dns.resolver
from typing import Dict, Any, Optional, List, Set

from .base import BaseModule


class SPFAnalyzerModule(BaseModule):
    name = "spf_analyzer"
    description = "Deep SPF record analysis — flattens include chains, counts DNS lookups, detects mail spoofing risk."
    category = "DNS & Domain Intelligence"
    dependencies = []

    MAX_RECURSION = 10

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        results = {
            "domain": domain,
            "spf_record": None,
            "has_spf": False,
            "lookup_count": 0,
            "max_lookups": 10,
            "exceeds_limit": False,
            "policy": None,
            "all_includes": [],
            "authorized_ips": [],
            "authorized_networks": [],
            "issues": [],
            "score": 0,
            "grade": "F",
        }

        loop = asyncio.get_event_loop()
        spf_record = await loop.run_in_executor(None, self._get_spf_record, domain)

        if not spf_record:
            results["issues"].append("No SPF record found — domain is vulnerable to email spoofing")
            return results

        results["spf_record"] = spf_record
        results["has_spf"] = True

        # Parse the SPF record
        visited: Set[str] = set()
        include_chain = []
        ips = []
        networks = []
        lookup_count = [0]  # Mutable to track across recursion

        await loop.run_in_executor(
            None, self._flatten_spf, domain, spf_record, visited,
            include_chain, ips, networks, lookup_count, 0
        )

        results["lookup_count"] = lookup_count[0]
        results["exceeds_limit"] = lookup_count[0] > 10
        results["all_includes"] = include_chain
        results["authorized_ips"] = ips[:100]
        results["authorized_networks"] = networks[:100]

        # Analyze policy
        if "+all" in spf_record:
            results["policy"] = "pass_all"
            results["issues"].append("CRITICAL: SPF uses +all (pass all) — anyone can spoof emails from this domain")
        elif "~all" in spf_record:
            results["policy"] = "softfail"
            results["issues"].append("SPF uses ~all (softfail) — spoofed emails may still be delivered")
            results["score"] += 40
        elif "-all" in spf_record:
            results["policy"] = "hardfail"
            results["score"] += 60
        elif "?all" in spf_record:
            results["policy"] = "neutral"
            results["issues"].append("SPF uses ?all (neutral) — provides no protection against spoofing")
        else:
            results["policy"] = "implicit_pass"
            results["issues"].append("SPF has no 'all' mechanism — defaults to pass")

        if results["exceeds_limit"]:
            results["issues"].append(
                f"SPF exceeds 10 DNS lookup limit ({lookup_count[0]} lookups) — "
                "causes PermError on receiving mail servers, effectively breaking SPF"
            )
        else:
            results["score"] += 20

        # Check for common issues
        if "ptr" in spf_record.lower():
            results["issues"].append("SPF uses deprecated 'ptr' mechanism — slow and unreliable")

        if len(include_chain) > 5:
            results["issues"].append(f"Complex SPF with {len(include_chain)} includes — consider flattening")

        # DMARC check
        dmarc = await loop.run_in_executor(None, self._check_dmarc, domain)
        results["dmarc"] = dmarc
        if dmarc.get("found"):
            results["score"] += 20
            if dmarc.get("policy") == "reject":
                results["score"] += 10

        # Grade
        if results["score"] >= 90:
            results["grade"] = "A"
        elif results["score"] >= 70:
            results["grade"] = "B"
        elif results["score"] >= 50:
            results["grade"] = "C"
        elif results["score"] >= 30:
            results["grade"] = "D"

        return results

    def _get_spf_record(self, domain: str) -> Optional[str]:
        """Get SPF TXT record for domain."""
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return txt
        except Exception:
            pass
        return None

    def _flatten_spf(self, domain: str, spf_record: str, visited: Set[str],
                     includes: list, ips: list, networks: list,
                     lookup_count: list, depth: int):
        """Recursively flatten SPF record, counting DNS lookups."""
        if depth > self.MAX_RECURSION or domain in visited:
            return
        visited.add(domain)

        parts = spf_record.split()
        for part in parts:
            mechanism = part.lstrip("+-~?")

            if mechanism.startswith("include:"):
                target = mechanism.split(":", 1)[1]
                lookup_count[0] += 1
                includes.append({"domain": target, "depth": depth, "from": domain})

                # Recursively resolve
                sub_spf = self._get_spf_record(target)
                if sub_spf:
                    self._flatten_spf(
                        target, sub_spf, visited, includes,
                        ips, networks, lookup_count, depth + 1
                    )

            elif mechanism.startswith("redirect="):
                target = mechanism.split("=", 1)[1]
                lookup_count[0] += 1
                includes.append({"domain": target, "depth": depth, "from": domain, "type": "redirect"})

                sub_spf = self._get_spf_record(target)
                if sub_spf:
                    self._flatten_spf(
                        target, sub_spf, visited, includes,
                        ips, networks, lookup_count, depth + 1
                    )

            elif mechanism.startswith("a"):
                lookup_count[0] += 1
                if ":" in mechanism:
                    target = mechanism.split(":", 1)[1]
                    if "/" in target:
                        networks.append(target)

            elif mechanism.startswith("mx"):
                lookup_count[0] += 1

            elif mechanism.startswith("exists:"):
                lookup_count[0] += 1

            elif mechanism.startswith("ip4:"):
                addr = mechanism.split(":", 1)[1]
                if "/" in addr:
                    networks.append(addr)
                else:
                    ips.append(addr)

            elif mechanism.startswith("ip6:"):
                addr = mechanism.split(":", 1)[1]
                networks.append(addr)

    def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Check DMARC record."""
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=DMARC1" in txt:
                    policy = "none"
                    if "p=reject" in txt:
                        policy = "reject"
                    elif "p=quarantine" in txt:
                        policy = "quarantine"
                    return {"found": True, "record": txt, "policy": policy}
        except Exception:
            pass
        return {"found": False}
