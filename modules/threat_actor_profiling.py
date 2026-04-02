import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
import os
import json

from .base import BaseModule

class ThreatActorProfilingModule(BaseModule):
    name = "threat_actor_profiling"
    description = "Maps observed TTPs to known Threat Actor groups (ATT&CK)."
    category = "Threat Intelligence"
    # Needs threat intel correlation to run first to grab TTPs
    dependencies = ["threat_intel_correlation"]
    
    # Default built-in DB
    DEFAULT_ACTORS = {
        "Lazarus Group": {
            "origin": "North Korea",
            "ttps": ["T1590", "T1204", "T1078", "T1059", "T1056"],
            "targets": ["Financial", "Crypto", "Entertainment"],
            "description": "State-sponsored cyber threat group attributed to North Korea."
        },
        "APT29 (Cozy Bear)": {
            "origin": "Russia",
            "ttps": ["T1589", "T1592", "T1190", "T1078"],
            "targets": ["Government", "Healthcare", "Think Tanks"],
            "description": "Russian Foreign Intelligence Service (SVR) cyber group."
        },
        "Mustang Panda": {
            "origin": "China",
            "ttps": ["T1588", "T1566", "T1059"],
            "targets": ["Government", "NGOs", "Telecommunications"],
            "description": "Chinese cyber espionage group."
        },
        "Indonesian Default Profiling": {
            "origin": "Local/Regional",
            "ttps": ["T1190", "T1566", "T1059.007"],
            "targets": ["E-commerce", "Gov ID"],
            "description": "Custom signature for regional low-sophistication attacks."
        }
    }
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Extract MITRE techniques from shared_state
        observed_ttps = set()
        
        # Look in threat correlation
        if "threat_intel_correlation" in shared_state:
            intel = shared_state["threat_intel_correlation"]
            for mapping in intel.get("mitre_attack", []):
                observed_ttps.add(mapping.get("technique_id"))
                
        # Look in infostealer logs
        if "infostealer_log_correlation" in shared_state:
            intel = shared_state["infostealer_log_correlation"]
            for mapping in intel.get("mitre_attack", []):
                observed_ttps.add(mapping.get("technique_id"))
                
        actors_db = self._load_custom_actors()
        
        profiles = self._calculate_profiles(observed_ttps, actors_db)
        
        highest_confidence = "Unknown"
        top_group = None
        if profiles and profiles[0]["confidence_score"] > 20:
            top_group = profiles[0]
            if top_group["confidence_score"] > 60:
                highest_confidence = f"High confidence: APT group consistent with {top_group['name']} profile"
            else:
                highest_confidence = f"Medium confidence: TTPs partially align with {top_group['name']}"
                
        return {
            "observed_ttps": list(observed_ttps),
            "highest_confidence_finding": highest_confidence,
            "profiles_matched": profiles
        }

    def _load_custom_actors(self) -> Dict[str, Any]:
        """Load actors.json from the same directory if it exists."""
        db = self.DEFAULT_ACTORS.copy()
        db_path = os.path.join(os.path.dirname(__file__), "actors.json")
        if os.path.exists(db_path):
            try:
                with open(db_path, "r") as f:
                    custom_db = json.load(f)
                    db.update(custom_db)
            except Exception:
                pass
        return db

    def _calculate_profiles(self, observed_ttps: set, db: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not observed_ttps:
            return []
            
        profiles = []
        for name, data in db.items():
            overlap = observed_ttps.intersection(set(data["ttps"]))
            if overlap:
                # Basic similarity scoring
                # Score based on how many of the target's TTPs were matched
                score = (len(overlap) / len(data["ttps"])) * 100
                profiles.append({
                    "name": name,
                    "origin": data.get("origin"),
                    "matched_ttps": list(overlap),
                    "confidence_score": round(score, 2),
                    "description": data.get("description")
                })
                
        # Sort by highest confidence
        return sorted(profiles, key=lambda x: x["confidence_score"], reverse=True)
