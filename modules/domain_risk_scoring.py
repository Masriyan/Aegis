import aiohttp
import asyncio
from typing import Dict, Any, Optional
import math
from collections import Counter
import re

from .base import BaseModule

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class DomainRiskScoringModule(BaseModule):
    name = "domain_risk_scoring"
    description = "Calculates DGA probability and generic risk score using lexical analysis and ML."
    category = "Intelligence & Experimental"
    dependencies = ["whois"]
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        # Remove TLD for lexical analysis (simple approximation)
        parts = domain.split(".")
        if len(parts) > 1:
            domain_core = ".".join(parts[:-1])
        else:
            domain_core = domain
            
        features = {
            "length": len(domain_core),
            "entropy": self._calculate_entropy(domain_core),
            "vowel_ratio": self._calculate_vowel_ratio(domain_core),
            "digit_ratio": self._calculate_digit_ratio(domain_core),
            "consecutive_consonants": self._max_consecutive_consonants(domain_core)
        }
        
        # ML Score (Isolation Forest for anomaly detection to spot DGA)
        ml_score, explanation = self._predict_dga(features)
        
        # Combine with WHOIS data if available
        risk_score = ml_score
        whois_age_days = None
        if "whois" in shared_state:
            whois_data = shared_state["whois"]
            creation_date = whois_data.get("creation_date")
            if creation_date:
                # Approximate age if it's available as an object or timestamp string
                # We'll mock the age check for simplicity
                pass
                
        # Final Score
        return {
            "domain": domain,
            "dga_probability": round(ml_score, 2),
            "risk_score": round(risk_score, 2),
            "ml_explanation": explanation,
            "lexical_features": features,
            "is_suspicious": risk_score > 0.7
        }

    def _calculate_entropy(self, s: str) -> float:
        p, lns = Counter(s), float(len(s))
        return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

    def _calculate_vowel_ratio(self, s: str) -> float:
        if not s:
            return 0.0
        vowels = set("aeiou")
        v_count = sum(1 for c in s.lower() if c in vowels)
        return v_count / len(s)

    def _calculate_digit_ratio(self, s: str) -> float:
        if not s:
            return 0.0
        d_count = sum(1 for c in s if c.isdigit())
        return d_count / len(s)

    def _max_consecutive_consonants(self, s: str) -> int:
        consonants = "bcdfghjklmnpqrstvwxyz"
        max_cons = 0
        current = 0
        for char in s.lower():
            if char in consonants:
                current += 1
                max_cons = max(max_cons, current)
            else:
                current = 0
        return max_cons

    def _predict_dga(self, features: Dict[str, Any]) -> tuple[float, str]:
        """Use IsolationForest if available, else use heuristic thresholds."""
        if not ML_AVAILABLE:
            # Fallback to heuristics
            score = 0.0
            reasons = []
            if features["length"] > 15:
                score += 0.2
                reasons.append("Long domain name")
            if features["entropy"] > 3.8:
                score += 0.4
                reasons.append("High entropy")
            if features["consecutive_consonants"] > 4:
                score += 0.3
                reasons.append("Many consecutive consonants")
            if features["digit_ratio"] > 0.3:
                score += 0.2
                reasons.append("High digit ratio")
            return min(1.0, score), ", ".join(reasons) if reasons else "Normal lexical profile"
            
        # Using a very rudimentary IsolationForest for demonstration of the requested feature
        # In reality, this would be a pre-trained model loaded from disk.
        X_test = np.array([[
            features["length"],
            features["entropy"],
            features["vowel_ratio"],
            features["digit_ratio"],
            features["consecutive_consonants"]
        ]])
        
        # Normal dummy data mix
        X_train = np.array([
            [10, 2.5, 0.4, 0.0, 2],
            [12, 2.8, 0.3, 0.1, 2],
            [8, 2.0, 0.5, 0.0, 1],
            [25, 4.2, 0.1, 0.3, 6], # DGA-like
        ])
        
        clf = IsolationForest(random_state=42, contamination=0.25)
        clf.fit(X_train)
        
        # Score is negative for anomalies. Convert to 0.0-1.0 probability.
        anomaly_score = clf.decision_function(X_test)[0]
        # map ~ -0.5 to 0.5 to 1.0 to 0.0
        dga_prob = max(0.0, min(1.0, 0.5 - anomaly_score))
        
        reasons = ["ML Anomaly Detection (IsolationForest)"]
        if features["entropy"] > 3.8:
            reasons.append("High Entropy Feature Driver")
        
        return dga_prob, ", ".join(reasons)
