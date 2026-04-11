"""
Cloud Storage Bucket Enumeration

Probes for publicly accessible cloud storage buckets (S3, Azure, GCP)
based on the target domain name and common naming patterns.
No API keys required — uses direct HTTP probing.
"""

import aiohttp
import asyncio
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from .base import BaseModule


class CloudBucketModule(BaseModule):
    name = "cloud_buckets"
    description = "Enumerates publicly accessible S3, Azure Blob, and GCP storage buckets based on domain keywords."
    category = "Discovery & Fingerprinting"
    dependencies = []
    rate_limit_rpm = 60

    # Bucket URL templates
    AWS_TEMPLATES = [
        "https://{keyword}.s3.amazonaws.com",
        "https://s3.amazonaws.com/{keyword}",
        "https://{keyword}.s3.us-east-1.amazonaws.com",
        "https://{keyword}.s3.us-west-2.amazonaws.com",
        "https://{keyword}.s3.eu-west-1.amazonaws.com",
        "https://{keyword}.s3.ap-southeast-1.amazonaws.com",
    ]

    AZURE_TEMPLATES = [
        "https://{keyword}.blob.core.windows.net",
        "https://{keyword}.file.core.windows.net",
        "https://{keyword}.table.core.windows.net",
        "https://{keyword}.queue.core.windows.net",
    ]

    GCP_TEMPLATES = [
        "https://storage.googleapis.com/{keyword}",
        "https://{keyword}.storage.googleapis.com",
    ]

    DO_TEMPLATES = [
        "https://{keyword}.nyc3.digitaloceanspaces.com",
        "https://{keyword}.ams3.digitaloceanspaces.com",
        "https://{keyword}.sgp1.digitaloceanspaces.com",
    ]

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Generate keyword variations from domain
        keywords = self._generate_keywords(domain)

        results = {
            "domain": domain,
            "keywords_tested": keywords,
            "buckets_found": [],
            "total_tested": 0,
            "public_buckets": 0,
            "private_buckets": 0,
        }

        # Build all URLs to probe
        urls_to_probe = []
        for keyword in keywords:
            for template in self.AWS_TEMPLATES:
                urls_to_probe.append(("aws_s3", template.format(keyword=keyword), keyword))
            for template in self.AZURE_TEMPLATES:
                urls_to_probe.append(("azure_blob", template.format(keyword=keyword), keyword))
            for template in self.GCP_TEMPLATES:
                urls_to_probe.append(("gcp_storage", template.format(keyword=keyword), keyword))
            for template in self.DO_TEMPLATES:
                urls_to_probe.append(("digitalocean", template.format(keyword=keyword), keyword))

        results["total_tested"] = len(urls_to_probe)

        # Probe in batches of 10 to be respectful
        batch_size = 10
        for i in range(0, len(urls_to_probe), batch_size):
            batch = urls_to_probe[i:i + batch_size]
            tasks = [self._probe_bucket(session, provider, url, kw) for provider, url, kw in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, dict) and result.get("exists"):
                    results["buckets_found"].append(result)
                    if result.get("public"):
                        results["public_buckets"] += 1
                    else:
                        results["private_buckets"] += 1

            await asyncio.sleep(0.3)  # Rate limit

        # Risk assessment
        if results["public_buckets"] > 0:
            results["risk_assessment"] = (
                f"CRITICAL: {results['public_buckets']} publicly accessible bucket(s) found. "
                "Data may be exposed to the internet."
            )
            results["severity"] = "critical"
        elif results["private_buckets"] > 0:
            results["risk_assessment"] = (
                f"Found {results['private_buckets']} bucket(s) (access denied). "
                "Buckets exist but are properly restricted."
            )
            results["severity"] = "info"
        else:
            results["risk_assessment"] = "No cloud storage buckets found for common naming patterns."
            results["severity"] = "info"

        return results

    def _generate_keywords(self, domain: str) -> List[str]:
        """Generate keyword variations from domain name."""
        parts = domain.split(".")
        base = parts[0]  # e.g., "target" from "target.com"

        keywords = set()
        keywords.add(base)
        keywords.add(domain.replace(".", "-"))  # target-com

        # Common suffixes/prefixes
        suffixes = [
            "", "-dev", "-staging", "-prod", "-backup", "-assets",
            "-media", "-static", "-uploads", "-data", "-logs",
            "-images", "-files", "-archive", "-public", "-private",
            "-internal", "-test", "-demo", "-cdn", "-web", "-api",
            "-docs", "-db", "-backups", "-config",
        ]

        for suffix in suffixes:
            keywords.add(f"{base}{suffix}")

        # Also try with a dot-separated subdomain prefix pattern
        if len(parts) >= 2:
            full = f"{parts[0]}-{parts[1]}"
            keywords.add(full)

        return list(keywords)[:50]  # Cap at 50 keywords

    async def _probe_bucket(self, session: aiohttp.ClientSession, provider: str,
                            url: str, keyword: str) -> Dict[str, Any]:
        """Probe a single bucket URL."""
        result = {
            "provider": provider,
            "url": url,
            "keyword": keyword,
            "exists": False,
            "public": False,
            "status": None,
        }

        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with session.get(url, timeout=timeout, allow_redirects=False) as resp:
                result["status"] = resp.status

                if resp.status == 200:
                    result["exists"] = True
                    text = await resp.text()

                    # S3 listings contain <ListBucketResult>
                    if "<ListBucketResult" in text or "<Contents>" in text:
                        result["public"] = True
                        result["listing_enabled"] = True
                    # GCP returns JSON listing
                    elif '"kind": "storage#objects"' in text:
                        result["public"] = True
                        result["listing_enabled"] = True
                    # Azure blobs
                    elif "<EnumerationResults" in text:
                        result["public"] = True
                        result["listing_enabled"] = True
                    else:
                        result["public"] = True
                        result["listing_enabled"] = False

                elif resp.status == 403:
                    # Bucket exists but access denied (expected/good)
                    result["exists"] = True
                    result["public"] = False

                elif resp.status in [301, 307]:
                    # Redirect — bucket exists
                    result["exists"] = True
                    result["public"] = False
                    result["redirect"] = resp.headers.get("Location", "")

                # 404 = does not exist — we skip

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        return result
