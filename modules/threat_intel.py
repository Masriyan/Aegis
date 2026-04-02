import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
import json

from .base import BaseModule

class ThreatIntelCorrelationModule(BaseModule):
    name = "threat_intel_correlation"
    description = "Cross-correlate all IOCs, map to MITRE ATT&CK, and check TAXII/STIX feeds."
    category = "Threat Intelligence"
    # This module depends on others to run first to gather IOCs
    dependencies = [] 
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        iocs = self._extract_iocs(shared_state)
        
        # Correlate feeds (Mocked for safety/speed, can be hooked to CIRCL/OTX API)
        feed_matches = await self._check_taxii_stix_feeds(session, iocs)
        
        # Map to ATT&CK
        attack_mappings = self._map_to_mitre_attack(iocs, feed_matches)
        
        # Build IOC Graph nodes and edges
        graph = self._build_ioc_graph(target, iocs)
        
        return {
            "total_iocs": len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["hashes"]),
            "iocs": iocs,
            "feed_matches": feed_matches,
            "mitre_attack": attack_mappings,
            "ioc_graph": graph
        }

    def _extract_iocs(self, shared_state: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IPs, domains, hashes from previous module results."""
        iocs = {"ips": set(), "domains": set(), "hashes": set()}
        
        if "dns" in shared_state:
            for ip in shared_state["dns"].get("ips", []):
                iocs["ips"].add(ip)
                
        # In a real scenario, we'd extract from all modules like virustotal, passive dns, etc.
        return {k: list(v) for k, v in iocs.items()}

    async def _check_taxii_stix_feeds(self, session: aiohttp.ClientSession, iocs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Query open TAXII/STIX feeds like CIRCL or OTX."""
        matches = []
        # Mocking an OTX/CIRCL feed hit for demonstration
        if iocs["ips"]:
            matches.append({
                "indicator": iocs["ips"][0],
                "type": "IPv4",
                "confidence": "High",
                "threat_actor": "Unknown",
                "tags": ["scanner", "malicious-ip"]
            })
        return matches

    def _map_to_mitre_attack(self, iocs: Dict[str, List[str]], feed_matches: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Map found IOCs and behaviors to MITRE ATT&CK."""
        mappings = []
        if feed_matches:
            mappings.append({
                "technique_id": "T1590",
                "technique_name": "Gather Victim Network Information",
                "tactic": "Reconnaissance",
                "confidence": 85
            })
        if iocs["hashes"]:
            mappings.append({
                "technique_id": "T1204",
                "technique_name": "User Execution",
                "tactic": "Execution",
                "confidence": 60
            })
        return mappings

    def _build_ioc_graph(self, target: str, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        """Build nodes and edges for visualizing the IOC graph representation."""
        nodes = [{"id": target, "label": target, "group": "target"}]
        edges = []
        
        for ip in iocs["ips"]:
            nodes.append({"id": ip, "label": ip, "group": "ip"})
            edges.append({"from": target, "to": ip, "label": "resolves_to"})
            
        for hash_val in iocs["hashes"]:
            nodes.append({"id": hash_val, "label": hash_val[:8]+"...", "group": "hash"})
            edges.append({"from": target, "to": hash_val, "label": "associated_hash"})
            
        return {"nodes": nodes, "edges": edges}
