import aiohttp
import asyncio
from typing import Dict, Any, Optional

from .base import BaseModule

class NetworkTopologyMapperModule(BaseModule):
    name = "network_topology"
    description = "Traces AS paths and flags high-risk hosting providers."
    category = "DNS & Domain Intelligence"
    dependencies = ["dns"]
    
    HIGH_RISK_ASNS = {
        "AS36352": "AS-COLOCROSSING",
        "AS61317": "Hivelocity",
        "AS200557": "Baehost",
        "AS8972": "HostPalace",
        "AS41364": "Telemax",
        "AS204746": "UAB Cherry Servers",
    }
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if "dns" not in shared_state:
            return {"error": "Missing DNS resolution data, cannot map topology without IPs."}
            
        ips = shared_state["dns"].get("ips", [])
        if not ips:
            return {"error": "No IPs found for target."}
            
        target_ip = ips[0]
        
        # 1. Query RIPE Stat for ASN Prefix info
        asn_data = await self._query_ripe_network_info(session, target_ip)
        if not asn_data:
            return {"error": "Could not determine ASN from RIPE."}
            
        asn = asn_data.get("asn")
        country = asn_data.get("country")
        holder = asn_data.get("holder", "Unknown")
        
        # 2. Extract CDN details if present
        is_cdn = self._check_cdn(holder)
        
        # 3. Simulate traceroute / origin mapping
        # Since raw traceroute requires root/ICMP, we build the logical graph
        topology_path = [target.replace("https://", "").replace("http://", "").split("/")[0]]
        if is_cdn:
            topology_path.append(f"CDN Nodes ({holder})")
        topology_path.append(f"{target_ip} ({asn})")
        topology_path.append(f"Country: {country}")
        
        # 4. Filter High Risk
        high_risk = asn in self.HIGH_RISK_ASNS
        risk_details = self.HIGH_RISK_ASNS.get(asn, "")
        
        return {
            "target_ip": target_ip,
            "asn": asn,
            "holder": holder,
            "country": country,
            "is_cdn": is_cdn,
            "topology_path": " -> ".join(topology_path),
            "hosted_in_high_risk_asn": high_risk,
            "risk_details": risk_details
        }

    async def _query_ripe_network_info(self, session: aiohttp.ClientSession, ip: str) -> Optional[Dict[str, Any]]:
        # RIPE stat API: getting prefix routing info
        url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    asns = data.get("data", {}).get("asns", [])
                    if asns:
                        return {
                            "asn": f"AS{asns[0]}",
                            "country": "Unknown", # Requires geostat API
                            "holder": "RIPE Stat Holder"
                        }
        except Exception:
            pass
            
        # Fallback to ip-api.com for country/ASN
        url2 = f"http://ip-api.com/json/{ip}"
        try:
            async with session.get(url2, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    asn_string = data.get("as", "")
                    asn_code = asn_string.split(" ")[0] if asn_string else "Unknown"
                    return {
                        "asn": asn_code,
                        "country": data.get("countryCode", "Unknown"),
                        "holder": asn_string
                    }
        except Exception:
            pass
            
        return None
        
    def _check_cdn(self, holder: str) -> bool:
        cdns = ["cloudflare", "fastly", "akamai", "amazon", "cloudfront", "incapsula"]
        holder_lower = holder.lower()
        return any(cdn in holder_lower for cdn in cdns)
