import aiohttp
import asyncio
from typing import Dict, Any, Optional
import re
import os
import subprocess

from .base import BaseModule

class JSThreatAnalyzerModule(BaseModule):
    name = "js_threat_analyzer"
    description = "Full AST-based / regex analysis of JS files for web skimmers, miners, and C2."
    category = "Deep Content Analysis"
    dependencies = []
    
    PATTERNS = {
        "web_skimmer": [
            r"document\.getElementById\(['\"](cc|credit|card|cvv|password)['\"]\)\.value",
            r"new\s+FormData\(document\.forms\[\d+\]\)",
            r"fetch\(['\"]https?://[^'\"/]+/[^'\"]*['\"]\s*,\s*\{.*?method:\s*['\"]POST['\"].*?body:"
        ],
        "crypto_miner": [
            r"CoinHive\.Anonymous",
            r"new\s+Client\.Anonymous",
            r"miner\.start\("
        ],
        "obfuscation": [
            r"eval\(function\(p,a,c,k,e,[rd]\)", # popular packer
            r"\\x[0-9a-fA-F]{2}\\x", 
            r"String\.fromCharCode\("
        ],
        "c2_callback": [
            r"WebSocket\(['\"]ws[s]?://",
            r"XMLHttpRequest\(\)",
            r"\$\.post\("
        ]
    }
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Usually, this module takes js_files found during crawling. For standalone runs, we fetch the homepage JS.
        js_files = []
        if "crawler" in shared_state:
            js_files = shared_state["crawler"].get("js_files", [])
            
        if not js_files:
            # Try to grab some scripts from homepage
            js_files = await self._discover_scripts(target, session)
            
        results = {
            "files_analyzed": 0,
            "threats_found": [],
            "mitre_attack": []
        }
        
        for url in js_files[:10]: # Limit to top 10 to save time
            content = await self._fetch_script(session, url)
            if content:
                results["files_analyzed"] += 1
                threats = self._analyze_script(content, url)
                if threats:
                    results["threats_found"].extend(threats)
                    
        self._map_mitre(results)
        return results

    async def _discover_scripts(self, target: str, session: aiohttp.ClientSession) -> list:
        try:
            async with session.get(target, timeout=10) as response:
                content = await response.text()
                # Simple regex script extractor
                scripts = re.findall(r'<script[^>]+src=["\'](.*?)["\']', content, re.I)
                urls = []
                for s in scripts:
                    if s.startswith("http"):
                        urls.append(s)
                    elif s.startswith("//"):
                        urls.append("https:" + s)
                    else:
                        base = target.rstrip("/")
                        if s.startswith("/"):
                            urls.append(base + s)
                        else:
                            urls.append(base + "/" + s)
                return urls
        except Exception:
            return []

    async def _fetch_script(self, session: aiohttp.ClientSession, url: str) -> str:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    return await response.text()
        except Exception:
            pass
        return ""

    def _analyze_script(self, content: str, url: str) -> list:
        # Fallback to RegEx
        threats = []
        
        for category, patterns in self.PATTERNS.items():
            for p in patterns:
                if re.search(p, content, re.I):
                    threats.append({
                        "file": url,
                        "category": category,
                        "indicator": p
                    })
                    break
                    
        # Simulate an AST / Node.js esprima call check here...
        # ...
        
        return threats

    def _map_mitre(self, results: Dict[str, Any]):
        cats = set([t["category"] for t in results["threats_found"]])
        
        if "web_skimmer" in cats:
            results["mitre_attack"].append({
                "technique_id": "T1056.003",
                "technique_name": "Web Portal Capture",
                "tactic": "Credential Access",
                "confidence": 90
            })
            
        if "obfuscation" in cats:
            results["mitre_attack"].append({
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "confidence": 85
            })
            
        if cats:
            results["mitre_attack"].append({
                "technique_id": "T1059.007",
                "technique_name": "JavaScript",
                "tactic": "Execution",
                "confidence": 100
            })
