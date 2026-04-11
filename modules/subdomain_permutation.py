"""
Subdomain Permutation Engine

Generates smart subdomain mutations from discovered subdomains
using altdns/dnsgen-style permutation techniques. Typically finds
10x more subdomains than basic bruteforce.
"""

import aiohttp
import asyncio
import dns.resolver
from typing import Dict, Any, Optional, List, Set
from itertools import product

from .base import BaseModule


class SubdomainPermutationModule(BaseModule):
    name = "subdomain_permutation"
    description = "Smart subdomain mutation engine — generates permutations from discovered subdomains to find hidden assets."
    category = "DNS & Domain Intelligence"
    dependencies = ["subdomain_scan"]
    rate_limit_rpm = 200

    # Common environment/function words for permutation
    WORDS = [
        "dev", "staging", "stage", "stg", "prod", "production",
        "test", "testing", "qa", "uat", "sandbox",
        "internal", "private", "corp", "intra", "vpn",
        "admin", "panel", "manage", "mgmt", "dashboard",
        "api", "api2", "api3", "apiv2", "rest", "graphql",
        "app", "web", "www2", "portal",
        "mail", "email", "smtp", "imap", "mx",
        "ftp", "sftp", "ssh", "rdp", "jump",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
        "cdn", "static", "assets", "media", "img", "images",
        "backup", "bak", "old", "legacy", "archive",
        "ci", "cd", "jenkins", "gitlab", "github", "drone",
        "docker", "k8s", "kube", "rancher", "swarm",
        "monitor", "grafana", "prometheus", "nagios", "kibana",
        "log", "logs", "elk", "sentry", "splunk",
        "cache", "memcached", "varnish", "proxy",
        "auth", "sso", "oauth", "login", "id", "identity",
        "ns1", "ns2", "ns3", "dns1", "dns2",
        "new", "next", "beta", "alpha", "v2", "v3",
    ]

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Get already-discovered subdomains from shared_state
        existing_subdomains = set()
        if "subdomain_scan" in shared_state:
            scan_data = shared_state["subdomain_scan"]
            for sub in scan_data.get("found", []):
                if isinstance(sub, str):
                    existing_subdomains.add(sub.lower())
                elif isinstance(sub, dict):
                    existing_subdomains.add(sub.get("subdomain", "").lower())

        results = {
            "domain": domain,
            "existing_subdomains": len(existing_subdomains),
            "permutations_generated": 0,
            "new_subdomains": [],
            "total_found": 0,
            "techniques_used": [],
        }

        # Generate permutations
        candidates = set()

        # Technique 1: Word insertion
        inserted = self._word_insertion(existing_subdomains, domain)
        candidates.update(inserted)
        results["techniques_used"].append(f"Word insertion: {len(inserted)} candidates")

        # Technique 2: Word prepend/append
        prepended = self._word_prepend_append(existing_subdomains, domain)
        candidates.update(prepended)
        results["techniques_used"].append(f"Word prepend/append: {len(prepended)} candidates")

        # Technique 3: Number mutations
        numbered = self._number_mutation(existing_subdomains, domain)
        candidates.update(numbered)
        results["techniques_used"].append(f"Number mutations: {len(numbered)} candidates")

        # Technique 4: Base word permutation (if no existing subs)
        if not existing_subdomains:
            base = self._base_permutations(domain)
            candidates.update(base)
            results["techniques_used"].append(f"Base permutations: {len(base)} candidates")

        # Remove already known subdomains and invalid entries
        candidates -= existing_subdomains
        candidates = {c for c in candidates if self._is_valid_subdomain(c, domain)}

        results["permutations_generated"] = len(candidates)

        # Resolve in batches
        loop = asyncio.get_event_loop()
        resolved = await loop.run_in_executor(
            None, self._resolve_batch, list(candidates)[:500]  # Cap at 500
        )

        results["new_subdomains"] = resolved
        results["total_found"] = len(resolved)

        if resolved:
            results["risk_assessment"] = (
                f"Discovered {len(resolved)} additional subdomains through permutation. "
                "Review for unauthorized services or shadow IT."
            )
        else:
            results["risk_assessment"] = "No additional subdomains found through permutation."

        return results

    def _word_insertion(self, subdomains: Set[str], domain: str) -> Set[str]:
        """Insert words between existing subdomain parts."""
        candidates = set()
        for sub in subdomains:
            # Strip domain suffix
            prefix = sub.replace(f".{domain}", "")
            if not prefix or prefix == sub:
                continue

            parts = prefix.split(".")
            for word in self.WORDS[:30]:  # Use top 30 words
                # Insert between parts
                for i in range(len(parts) + 1):
                    new_parts = parts[:i] + [word] + parts[i:]
                    candidates.add(".".join(new_parts) + f".{domain}")

                # Separator mutations
                for part in parts:
                    candidates.add(f"{part}-{word}.{domain}")
                    candidates.add(f"{word}-{part}.{domain}")

        return candidates

    def _word_prepend_append(self, subdomains: Set[str], domain: str) -> Set[str]:
        """Prepend/append common words to existing subdomains."""
        candidates = set()
        for sub in subdomains:
            prefix = sub.replace(f".{domain}", "")
            if not prefix or prefix == sub:
                continue

            for word in self.WORDS[:30]:
                candidates.add(f"{word}.{prefix}.{domain}")
                candidates.add(f"{prefix}.{word}.{domain}")
                candidates.add(f"{word}-{prefix}.{domain}")
                candidates.add(f"{prefix}-{word}.{domain}")
                candidates.add(f"{word}{prefix}.{domain}")
                candidates.add(f"{prefix}{word}.{domain}")

        return candidates

    def _number_mutation(self, subdomains: Set[str], domain: str) -> Set[str]:
        """Add number suffix/prefix mutations."""
        candidates = set()
        for sub in subdomains:
            prefix = sub.replace(f".{domain}", "")
            if not prefix or prefix == sub:
                continue

            for n in range(1, 6):
                candidates.add(f"{prefix}{n}.{domain}")
                candidates.add(f"{prefix}-{n}.{domain}")
                candidates.add(f"{prefix}0{n}.{domain}")

            # Strip trailing numbers and try alternatives
            import re
            base = re.sub(r'\d+$', '', prefix)
            if base and base != prefix:
                for n in range(1, 10):
                    candidates.add(f"{base}{n}.{domain}")

        return candidates

    def _base_permutations(self, domain: str) -> Set[str]:
        """Generate basic permutations when no existing subdomains known."""
        candidates = set()
        for word in self.WORDS:
            candidates.add(f"{word}.{domain}")
        return candidates

    def _is_valid_subdomain(self, candidate: str, domain: str) -> bool:
        """Basic validation of subdomain candidate."""
        if not candidate.endswith(f".{domain}"):
            return False
        prefix = candidate.replace(f".{domain}", "")
        if not prefix:
            return False
        if len(prefix) > 63:
            return False
        if ".." in candidate:
            return False
        if prefix.startswith("-") or prefix.endswith("-"):
            return False
        return True

    def _resolve_batch(self, candidates: List[str]) -> List[Dict[str, Any]]:
        """Resolve DNS for candidate subdomains."""
        found = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3

        for candidate in candidates:
            try:
                answers = resolver.resolve(candidate, "A")
                ips = [str(rdata) for rdata in answers]
                found.append({
                    "subdomain": candidate,
                    "ips": ips,
                    "source": "permutation",
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass

        return found
