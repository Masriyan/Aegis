import aiohttp
import asyncio
from typing import Dict, Any, Optional
import os
import base64

from .base import BaseModule

class InfostealerLogCorrelationModule(BaseModule):
    name = "infostealer_log_correlation"
    description = "Checks target domain against DeHashed and IntelligenceX for credential exposure."
    category = "Threat Intelligence"
    dependencies = []
    
    required_api_key_env = "DEHASHED_API_KEY"
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        dehashed_key = os.environ.get(self.required_api_key_env, "")
        dehashed_email = os.environ.get("DEHASHED_EMAIL", "")
        
        results = {
            "sources_checked": [],
            "breach_hits": 0,
            "compromised_accounts": [],
            "mitre_attack": []
        }
        
        if dehashed_key and dehashed_email:
            await self._query_dehashed(session, domain, dehashed_email, dehashed_key, results)
            
        intelx_key = os.environ.get("INTELX_API_KEY", "")
        if intelx_key:
            await self._query_intelligencex(session, domain, intelx_key, results)
            
        if results["breach_hits"] > 0:
            results["mitre_attack"].append({
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "Initial Access",
                "confidence": 95 if len(results["compromised_accounts"]) > 5 else 60
            })
            
        return results

    async def _query_dehashed(self, session: aiohttp.ClientSession, domain: str, email: str, api_key: str, results: Dict[str, Any]):
        url = f"https://api.dehashed.com/search?query=domain:{domain}"
        auth_string = f"{email}:{api_key}"
        auth_bytes = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {auth_bytes}"
        }
        try:
            async with session.get(url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    results["sources_checked"].append("DeHashed")
                    data = await response.json()
                    
                    entries = data.get("entries", [])
                    if entries:
                        results["breach_hits"] += len(entries)
                        for entry in entries[:10]: # Store up to 10 samples
                            results["compromised_accounts"].append({
                                "email": entry.get("email"),
                                "username": entry.get("username"),
                                "password": "***" if entry.get("password") else None,
                                "database_name": entry.get("database_name"),
                                "source": "DeHashed"
                            })
        except Exception:
            pass

    async def _query_intelligencex(self, session: aiohttp.ClientSession, domain: str, api_key: str, results: Dict[str, Any]):
        """IntelligenceX Search API."""
        url = "https://2.intelx.io/intelligent/search"
        headers = {
            "x-key": api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "term": domain,
            "maxresults": 10,
            "media": 0,
            "sort": 2,
            "terminate": []
        }
        try:
            async with session.post(url, headers=headers, json=payload, timeout=15) as response:
                if response.status == 200:
                    results["sources_checked"].append("IntelligenceX")
                    data = await response.json()
                    
                    search_id = data.get("id")
                    if search_id:
                        # Fetch the actual results (simplified for example)
                        fetch_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}"
                        async with session.get(fetch_url, headers=headers, timeout=15) as fetch_resp:
                            if fetch_resp.status == 200:
                                res_data = await fetch_resp.json()
                                records = res_data.get("records", [])
                                results["breach_hits"] += len(records)
                                for rec in records[:5]:
                                    results["compromised_accounts"].append({
                                        "name": rec.get("name"),
                                        "date": rec.get("date"),
                                        "bucket": rec.get("bucket"),
                                        "source": "IntelligenceX"
                                    })
        except Exception:
            pass
