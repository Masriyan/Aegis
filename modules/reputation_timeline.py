import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
import os
import json
from datetime import datetime

from .base import BaseModule

class ReputationTimelineModule(BaseModule):
    name = "reputation_timeline"
    description = "Pulls historical detections to show reputation trends and evading behaviors."
    category = "Threat Intelligence"
    dependencies = []
    
    required_api_key_env = "VT_API_KEY"
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        vt_key = os.environ.get(self.required_api_key_env, "")
        
        timeline = {
            "feeds_checked": [],
            "reputation_trend": "Unknown",
            "historical_detections": [],
            "evasion_detected": False,
            "malware_bazaar_matches": []
        }
        
        # Pull ThreatFox / MalwareBazaar (Open, no API key strictly needed for basic search)
        await self._query_threatfox(session, target, timeline)
        
        # Pull VT Historical data if key is present
        if vt_key:
            await self._query_vt_history(session, target, vt_key, timeline)
            
        self._analyze_trends(timeline)
        
        return timeline

    async def _query_threatfox(self, session: aiohttp.ClientSession, target: str, timeline: Dict[str, Any]):
        """Query ThreatFox for general IOCs associated with the domain/IP."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {
            "query": "search_ioc",
            "search_term": domain
        }
        try:
            async with session.post(url, json=payload, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("query_status") == "ok":
                        timeline["feeds_checked"].append("ThreatFox")
                        for ioc in data.get("data", []):
                            timeline["historical_detections"].append({
                                "source": "ThreatFox",
                                "date": ioc.get("first_seen"),
                                "malware_family": ioc.get("malware_printable"),
                                "confidence": ioc.get("confidence_level")
                            })
        except Exception:
            pass

    async def _query_vt_history(self, session: aiohttp.ClientSession, target: str, api_key: str, timeline: Dict[str, Any]):
        """Query VT historical resolutions and current detections."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        try:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    timeline["feeds_checked"].append("VirusTotal")
                    data = await response.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    
                    if stats.get("malicious", 0) > 0:
                        timeline["historical_detections"].append({
                            "source": "VirusTotal",
                            "date": datetime.now().isoformat(),
                            "malware_family": "Various",
                            "confidence": stats.get("malicious", 0) * 10
                        })
                        
                    # Historical resolutions
                    res_url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=10"
                    async with session.get(res_url, headers=headers, timeout=10) as res_response:
                        if res_response.status == 200:
                            res_data = await res_response.json()
                            for item in res_data.get("data", []):
                                date_str = datetime.fromtimestamp(item.get("attributes", {}).get("date", 0)).isoformat()
                                timeline["historical_detections"].append({
                                    "source": "VirusTotal Resolution History",
                                    "date": date_str,
                                    "ip": item.get("attributes", {}).get("ip_address"),
                                    "confidence": 0 # Not a detection, just history
                                })
        except Exception:
            pass

    def _analyze_trends(self, timeline: Dict[str, Any]):
        if not timeline["historical_detections"]:
            timeline["reputation_trend"] = "Clean"
            return
            
        detections = [d for d in timeline["historical_detections"] if d.get('confidence', 0) > 0]
        if len(detections) > 0:
            timeline["reputation_trend"] = "Malicious"
            if len(timeline["historical_detections"]) > 5:
                timeline["evasion_detected"] = True
                timeline["reputation_trend"] = "Volatile (Clean -> Flagged -> Clean behavior suspected)"
        else:
            timeline["reputation_trend"] = "Suspicious (History Found)"
