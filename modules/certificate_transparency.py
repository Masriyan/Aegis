import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from .base import BaseModule

class CertificateTransparencyModule(BaseModule):
    name = "cert_transparency"
    description = "Query crt.sh for certificate history, spotting wildcard certs and recent issuances."
    category = "Discovery & Fingerprinting"
    dependencies = []
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        certs = await self._query_crt_sh(session, domain)
        if not certs:
            return None
            
        analysis = self._analyze_certificates(certs, domain)
        
        return {
            "total_certificates_found": len(certs),
            "certificates": certs[:20],  # only return top 20 to save DB space
            "analysis": analysis
        }

    async def _query_crt_sh(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        url = f"https://crt.sh/?q={domain}&output=json"
        try:
            # Add timeout and user agent to prevent blocks
            async with session.get(url, timeout=15) as response:
                if response.status == 200:
                    text_data = await response.text()
                    try:
                        return json.loads(text_data)
                    except json.JSONDecodeError:
                        return []
        except Exception:
            return []
        return []

    def _analyze_certificates(self, certs: List[Dict[str, Any]], domain: str) -> Dict[str, Any]:
        analysis = {
            "wildcard_certs_found": False,
            "recent_issuance": False,
            "cert_reuse": False,
            "unique_issuers": set(),
            "flags": []
        }
        
        now = datetime.now()
        
        for cert in certs:
            # 1. Check for wildcard certs
            name_value = cert.get("name_value", "")
            if "*." in name_value:
                analysis["wildcard_certs_found"] = True
                if "Wildcard Certificate Detected (Subdomain Sprawl Risk)" not in analysis["flags"]:
                    analysis["flags"].append("Wildcard Certificate Detected (Subdomain Sprawl Risk)")
                    
            # 2. Track issuers
            issuer = cert.get("issuer_name", "")
            if issuer:
                analysis["unique_issuers"].add(issuer)
                
            # 3. Check issuance date (< 7 days)
            # format example: "2023-10-05T10:15:30"
            not_before = cert.get("not_before", "")
            if not_before:
                try:
                    issued_date = datetime.fromisoformat(not_before.split(".")[0])
                    delta = now - issued_date
                    if delta.days < 7 and delta.days >= 0:
                        analysis["recent_issuance"] = True
                        if "Recent Certificate Issuance (< 7 days) - Possible Phishing" not in analysis["flags"]:
                            analysis["flags"].append("Recent Certificate Issuance (< 7 days) - Possible Phishing")
                except Exception:
                    pass
                    
        # 4. Certificate Reuse
        if len(analysis["unique_issuers"]) > 3:
            analysis["cert_reuse"] = True
            analysis["flags"].append(f"Multiple Certificate Authorities ({len(analysis['unique_issuers'])} detected) - Possible infrastructure sharing.")
            
        analysis["unique_issuers"] = list(analysis["unique_issuers"])
        return analysis
