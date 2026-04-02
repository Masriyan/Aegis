import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
import os

from .base import BaseModule

class PassiveDNSHistoryModule(BaseModule):
    name = "passive_dns_history"
    description = "Query historical DNS records to detect fast-flux and compute infrastructure history."
    category = "DNS & Domain Intelligence"
    dependencies = []
    
    # Optional key for security trails
    required_api_key_env = "SECURITYTRAILS_API_KEY"
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        st_key = os.environ.get(self.required_api_key_env, "")
        
        history = {
            "sources": [],
            "records": [],
            "fast_flux_detected": False,
            "ip_changes_last_60_days": 0,
            "domain_fronting_indicators": []
        }
        
        if st_key:
            # Query SecurityTrails API
            st_data = await self._query_securitytrails(session, domain, st_key)
            if st_data:
                history["sources"].append("SecurityTrails")
                history["records"].extend(st_data.get("records", []))
                
        # Query HackerTarget API (free, rate limited)
        ht_data = await self._query_hackertarget(session, domain)
        if ht_data:
            history["sources"].append("HackerTarget")
            history["records"].extend(ht_data.get("records", []))
            
        # Analyze historical data for fast-flux
        self._analyze_history(history, domain)
        
        return history

    async def _query_securitytrails(self, session: aiohttp.ClientSession, domain: str, api_key: str) -> Optional[Dict[str, Any]]:
        headers = {
            "APIKEY": api_key,
            "Accept": "application/json"
        }
        hist_url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        try:
            response = await self.async_fetch(hist_url, session, headers=headers, timeout=10)
            if response and response.status == 200:
                data = await response.json()
                records = []
                for record in data.get("records", []):
                    records.append({
                        "type": "A",
                        "value": record["values"][0]["ip"],
                        "first_seen": record["first_seen"],
                        "last_seen": record["last_seen"]
                    })
                return {"records": records}
        except Exception:
            pass
        return None

    async def _query_hackertarget(self, session: aiohttp.ClientSession, domain: str) -> Optional[Dict[str, Any]]:
        """Query HackerTarget for passive DNS data (no API key required but rate limited)."""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            response = await self.async_fetch(url, session, timeout=15)
            if response and response.status == 200:
                text = await response.text()
                records = []
                for line in text.strip().split("\n"):
                    if "," in line:
                        hostname, ip = line.split(",", 1)
                        if domain in hostname:
                            records.append({"type": "A", "value": ip, "hostname": hostname, "source": "hackertarget"})
                return {"records": records}
        except Exception:
            pass
        return None

    def _analyze_history(self, history: Dict[str, Any], domain: str) -> None:
        """Analyze the aggregated records for malicious behavior indicators."""
        unique_ips = set()
        for rec in history["records"]:
            if rec["type"] == "A":
                unique_ips.add(rec["value"])
                
        history["unique_ip_count"] = len(unique_ips)
        
        # Fast flux heuristic: more than 5 unique IPs for a standard domain (excluding known CDNs)
        if len(unique_ips) > 5:
            # Check if any IP belongs to Cloudflare / Fastly to ignore CDN false positives
            history["fast_flux_detected"] = True
            
        history["ip_changes_last_60_days"] = len(unique_ips)
