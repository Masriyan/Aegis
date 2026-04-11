"""
Google Dorking Engine

Automates Google Dork queries to find:
- Exposed files (SQL dumps, backups, configs, logs)
- Admin panels and login pages
- Directory listings
- Credentials in paste sites
- Exposed documents

Uses Google Custom Search API if available, falls back to scraping-safe alternatives.
"""

import aiohttp
import asyncio
import os
import re
from typing import Dict, Any, Optional, List
from urllib.parse import quote_plus

from .base import BaseModule


class GoogleDorkModule(BaseModule):
    name = "google_dorking"
    description = "Automated Google dorking — finds exposed files, admin panels, backups, and credentials related to the target."
    category = "Tactical OSINT"
    dependencies = []
    rate_limit_rpm = 10  # Be very gentle with search engines

    # Dork categories with queries
    DORK_CATEGORIES = {
        "exposed_files": {
            "description": "Sensitive files exposed on the target",
            "dorks": [
                'site:{domain} filetype:sql',
                'site:{domain} filetype:env',
                'site:{domain} filetype:bak',
                'site:{domain} filetype:log',
                'site:{domain} filetype:conf',
                'site:{domain} filetype:cfg',
                'site:{domain} filetype:xml',
                'site:{domain} filetype:json inurl:config',
                'site:{domain} filetype:yml',
                'site:{domain} filetype:pem',
                'site:{domain} filetype:key',
            ],
        },
        "admin_panels": {
            "description": "Admin panel and management interfaces",
            "dorks": [
                'site:{domain} inurl:admin',
                'site:{domain} inurl:login',
                'site:{domain} inurl:dashboard',
                'site:{domain} inurl:panel',
                'site:{domain} inurl:manage',
                'site:{domain} intitle:"admin"',
                'site:{domain} inurl:wp-admin',
                'site:{domain} inurl:phpMyAdmin',
            ],
        },
        "directory_listings": {
            "description": "Open directory listings",
            "dorks": [
                'site:{domain} intitle:"index of"',
                'site:{domain} intitle:"directory listing"',
                'site:{domain} intitle:"parent directory"',
            ],
        },
        "credentials": {
            "description": "Potential credential exposure",
            "dorks": [
                '"{domain}" password filetype:txt',
                '"{domain}" password filetype:log',
                '"{domain}" password filetype:csv',
                '"{domain}" "api_key" OR "apikey" OR "api-key"',
                '"{domain}" "BEGIN RSA PRIVATE KEY"',
                '"{domain}" "AWS_SECRET_ACCESS_KEY"',
            ],
        },
        "paste_sites": {
            "description": "Credentials or data on paste sites",
            "dorks": [
                '"{domain}" site:pastebin.com',
                '"{domain}" site:paste.debian.net',
                '"{domain}" site:gist.github.com',
                '"{domain}" site:codepad.co',
                '"{domain}" site:trello.com',
            ],
        },
        "cloud_exposure": {
            "description": "Cloud service exposure",
            "dorks": [
                '"{domain}" site:amazonaws.com',
                '"{domain}" site:blob.core.windows.net',
                '"{domain}" site:storage.googleapis.com',
                '"{domain}" site:digitaloceanspaces.com',
            ],
        },
        "error_pages": {
            "description": "Exposed error/debug pages",
            "dorks": [
                'site:{domain} inurl:debug',
                'site:{domain} "stack trace"',
                'site:{domain} "internal server error"',
                'site:{domain} "PHP Warning"',
                'site:{domain} "SQL syntax"',
            ],
        },
    }

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        results = {
            "domain": domain,
            "categories_tested": 0,
            "dorks_generated": 0,
            "findings": [],
            "dork_list": [],
            "risk_assessment": "Info",
        }

        # Generate all dorks
        all_dorks = []
        for category_id, category in self.DORK_CATEGORIES.items():
            for dork_template in category["dorks"]:
                dork = dork_template.format(domain=domain)
                all_dorks.append({
                    "category": category_id,
                    "category_desc": category["description"],
                    "dork": dork,
                    "google_url": f"https://www.google.com/search?q={quote_plus(dork)}",
                })

        results["dorks_generated"] = len(all_dorks)
        results["categories_tested"] = len(self.DORK_CATEGORIES)
        results["dork_list"] = all_dorks

        # Try to search via free search APIs
        google_cse_key = os.getenv("GOOGLE_CSE_API_KEY", "")
        google_cse_cx = os.getenv("GOOGLE_CSE_CX", "")

        if google_cse_key and google_cse_cx:
            # Use Google Custom Search API (limited to 100 free queries/day)
            findings = await self._google_cse_search(
                session, all_dorks[:10], google_cse_key, google_cse_cx
            )
            results["findings"] = findings
            results["search_method"] = "google_cse_api"
        else:
            # Fallback: Use DuckDuckGo Lite (no API key needed)
            findings = await self._duckduckgo_search(session, all_dorks[:8], domain)
            results["findings"] = findings
            results["search_method"] = "duckduckgo_lite"

        # Risk assessment
        critical = sum(1 for f in results["findings"] if f.get("severity") in ["critical", "high"])
        if critical > 0:
            results["risk_assessment"] = f"HIGH: {critical} potentially critical exposure(s) found via dorking"
            results["severity"] = "high"
        elif results["findings"]:
            results["risk_assessment"] = f"Found {len(results['findings'])} result(s) — review for sensitive information"
            results["severity"] = "medium"
        else:
            results["risk_assessment"] = "No significant findings from dork queries"
            results["severity"] = "info"

        return results

    async def _google_cse_search(self, session: aiohttp.ClientSession,
                                  dorks: List[Dict], api_key: str, cx: str) -> List[Dict]:
        """Search using Google Custom Search Engine API."""
        findings = []

        for dork_info in dorks:
            try:
                url = "https://www.googleapis.com/customsearch/v1"
                params = {
                    "key": api_key,
                    "cx": cx,
                    "q": dork_info["dork"],
                    "num": 5,
                }
                async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("items", []):
                            findings.append({
                                "category": dork_info["category"],
                                "dork": dork_info["dork"],
                                "title": item.get("title", ""),
                                "url": item.get("link", ""),
                                "snippet": item.get("snippet", ""),
                                "severity": self._assess_severity(dork_info["category"], item),
                            })
                await asyncio.sleep(1)  # Rate limit
            except Exception:
                pass

        return findings

    async def _duckduckgo_search(self, session: aiohttp.ClientSession,
                                  dorks: List[Dict], domain: str) -> List[Dict]:
        """Search using DuckDuckGo Lite (no API key needed)."""
        findings = []

        for dork_info in dorks:
            try:
                url = "https://lite.duckduckgo.com/lite/"
                data = {"q": dork_info["dork"]}
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                }

                async with session.post(url, data=data, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        from bs4 import BeautifulSoup
                        text = await resp.text()
                        soup = BeautifulSoup(text, "html.parser")

                        # DuckDuckGo Lite results are in links
                        for link in soup.find_all("a", class_="result-link"):
                            href = link.get("href", "")
                            title = link.get_text(strip=True)
                            if href and domain in href:
                                # Get snippet from next sibling
                                snippet = ""
                                snippet_el = link.find_next("td", class_="result-snippet")
                                if snippet_el:
                                    snippet = snippet_el.get_text(strip=True)

                                findings.append({
                                    "category": dork_info["category"],
                                    "dork": dork_info["dork"],
                                    "title": title,
                                    "url": href,
                                    "snippet": snippet[:200],
                                    "severity": self._assess_severity(dork_info["category"], {"link": href}),
                                })
                await asyncio.sleep(2)  # Be gentle
            except Exception:
                pass

        return findings

    def _assess_severity(self, category: str, item: dict) -> str:
        """Assess finding severity based on category and content."""
        url = item.get("link", item.get("url", "")).lower()

        critical_patterns = [
            ".sql", ".bak", ".key", ".pem", "password",
            "BEGIN RSA", "AWS_SECRET", "api_key",
        ]
        for pattern in critical_patterns:
            if pattern in url or pattern in str(item.get("snippet", "")):
                return "critical"

        severity_map = {
            "exposed_files": "high",
            "credentials": "critical",
            "paste_sites": "high",
            "admin_panels": "medium",
            "directory_listings": "high",
            "cloud_exposure": "medium",
            "error_pages": "medium",
        }
        return severity_map.get(category, "info")
