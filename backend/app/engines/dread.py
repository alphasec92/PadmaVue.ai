"""
DREAD Risk Scoring Engine
Implements the DREAD methodology for threat risk assessment
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass
import numpy as np


class RiskLevel(str, Enum):
    """Risk level classifications"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DREADScore:
    """DREAD score result"""
    damage: float
    reproducibility: float
    exploitability: float
    affected_users: float
    discoverability: float
    score: float
    level: RiskLevel
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "damage": self.damage,
            "reproducibility": self.reproducibility,
            "exploitability": self.exploitability,
            "affected_users": self.affected_users,
            "discoverability": self.discoverability,
            "score": self.score,
            "level": self.level.value
        }


class DREADEngine:
    """
    DREAD Risk Scoring Engine.
    
    DREAD is a risk rating methodology:
    - Damage: How bad would an attack be?
    - Reproducibility: How easy is it to reproduce the attack?
    - Exploitability: How much work is it to launch the attack?
    - Affected Users: How many people will be impacted?
    - Discoverability: How easy is it to discover the threat?
    
    Each factor is rated 1-10, with the final score being a weighted average.
    """
    
    # Default weights for DREAD factors
    DEFAULT_WEIGHTS = {
        "damage": 1.0,
        "reproducibility": 1.0,
        "exploitability": 1.0,
        "affected_users": 1.0,
        "discoverability": 1.0
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        RiskLevel.CRITICAL: 8.0,
        RiskLevel.HIGH: 6.0,
        RiskLevel.MEDIUM: 4.0,
        RiskLevel.LOW: 2.0,
        RiskLevel.INFO: 0.0
    }
    
    # Descriptions for each DREAD factor
    FACTOR_DESCRIPTIONS = {
        "damage": {
            "name": "Damage Potential",
            "question": "How much damage will be caused if the threat is exploited?",
            "scale": {
                1: "Minimal impact, no significant damage",
                3: "Low impact, minor damage to single user",
                5: "Moderate impact, significant damage to subset of users",
                7: "High impact, major damage to many users or systems",
                10: "Maximum impact, complete system compromise or data breach"
            }
        },
        "reproducibility": {
            "name": "Reproducibility",
            "question": "How easy is it to reproduce the attack?",
            "scale": {
                1: "Very difficult, requires specific conditions",
                3: "Difficult, requires authentication or timing",
                5: "Moderate, reproducible with some effort",
                7: "Easy, can be reproduced with simple steps",
                10: "Trivial, can be reproduced every time"
            }
        },
        "exploitability": {
            "name": "Exploitability",
            "question": "How much effort is required to exploit the vulnerability?",
            "scale": {
                1: "Extremely difficult, requires expert knowledge",
                3: "Difficult, requires specialized tools",
                5: "Moderate, requires technical knowledge",
                7: "Easy, basic hacking skills needed",
                10: "Trivial, exploit is automated or publicly available"
            }
        },
        "affected_users": {
            "name": "Affected Users",
            "question": "How many users will be affected?",
            "scale": {
                1: "Individual user only",
                3: "Small group of users",
                5: "Significant portion of users",
                7: "Most users affected",
                10: "All users affected"
            }
        },
        "discoverability": {
            "name": "Discoverability",
            "question": "How easy is it to discover the vulnerability?",
            "scale": {
                1: "Very hard to discover, no public information",
                3: "Difficult, requires deep analysis",
                5: "Moderate, findable with security testing",
                7: "Easy, obvious to trained eye",
                10: "Trivial, publicly known or easily found"
            }
        }
    }
    
    def __init__(self, weights: Dict[str, float] = None):
        """
        Initialize DREAD engine with optional custom weights.
        
        Args:
            weights: Custom weights for each DREAD factor
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
    
    def calculate(
        self,
        damage: float,
        reproducibility: float,
        exploitability: float,
        affected_users: float,
        discoverability: float
    ) -> Dict[str, Any]:
        """
        Calculate DREAD score from individual factors.
        
        Args:
            damage: Damage potential (1-10)
            reproducibility: Reproducibility (1-10)
            exploitability: Exploitability (1-10)
            affected_users: Affected users (1-10)
            discoverability: Discoverability (1-10)
        
        Returns:
            DREAD score result with overall score and risk level
        """
        # Validate inputs
        factors = {
            "damage": self._clamp(damage),
            "reproducibility": self._clamp(reproducibility),
            "exploitability": self._clamp(exploitability),
            "affected_users": self._clamp(affected_users),
            "discoverability": self._clamp(discoverability)
        }
        
        # Calculate weighted average
        weighted_sum = sum(
            factors[k] * self.weights[k]
            for k in factors
        )
        total_weight = sum(self.weights.values())
        score = round(weighted_sum / total_weight, 2)
        
        # Determine risk level
        level = self._get_risk_level(score)
        
        return {
            "damage": factors["damage"],
            "reproducibility": factors["reproducibility"],
            "exploitability": factors["exploitability"],
            "affected_users": factors["affected_users"],
            "discoverability": factors["discoverability"],
            "score": score,
            "level": level.value
        }
    
    def calculate_from_dict(
        self,
        scores: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Calculate DREAD score from a dictionary.
        
        Args:
            scores: Dictionary with DREAD factor scores
        
        Returns:
            DREAD score result
        """
        return self.calculate(
            damage=scores.get("damage", 5),
            reproducibility=scores.get("reproducibility", 5),
            exploitability=scores.get("exploitability", 5),
            affected_users=scores.get("affected_users", 5),
            discoverability=scores.get("discoverability", 5)
        )
    
    def _clamp(self, value: float) -> float:
        """Clamp value to valid range (1-10)"""
        return max(1.0, min(10.0, float(value)))
    
    def _get_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        if score >= self.RISK_THRESHOLDS[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.RISK_THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.RISK_THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score >= self.RISK_THRESHOLDS[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def get_factor_guidance(self, factor: str) -> Dict[str, Any]:
        """Get guidance for scoring a DREAD factor"""
        return self.FACTOR_DESCRIPTIONS.get(factor, {})
    
    def get_all_guidance(self) -> Dict[str, Any]:
        """Get guidance for all DREAD factors"""
        return self.FACTOR_DESCRIPTIONS.copy()
    
    def estimate_from_description(
        self,
        threat_description: str,
        component_type: str = "process"
    ) -> Dict[str, float]:
        """
        Estimate DREAD scores from a threat description.
        Uses heuristics to provide initial estimates.
        
        Args:
            threat_description: Description of the threat
            component_type: Type of affected component
        
        Returns:
            Estimated DREAD scores
        """
        description_lower = threat_description.lower()
        
        # Initialize with baseline scores
        scores = {
            "damage": 5.0,
            "reproducibility": 5.0,
            "exploitability": 5.0,
            "affected_users": 5.0,
            "discoverability": 5.0
        }
        
        # Damage estimation
        if any(term in description_lower for term in ["complete compromise", "data breach", "total loss"]):
            scores["damage"] = 9.0
        elif any(term in description_lower for term in ["sensitive data", "credentials", "pii"]):
            scores["damage"] = 7.5
        elif any(term in description_lower for term in ["minor", "limited", "low impact"]):
            scores["damage"] = 3.0
        
        # Reproducibility estimation
        if any(term in description_lower for term in ["always", "trivial", "any time"]):
            scores["reproducibility"] = 9.0
        elif any(term in description_lower for term in ["specific conditions", "timing", "race"]):
            scores["reproducibility"] = 4.0
        
        # Exploitability estimation
        if any(term in description_lower for term in ["automated", "script", "public exploit"]):
            scores["exploitability"] = 9.0
        elif any(term in description_lower for term in ["expert", "complex", "advanced"]):
            scores["exploitability"] = 3.0
        
        # Affected users estimation
        if any(term in description_lower for term in ["all users", "everyone", "system-wide"]):
            scores["affected_users"] = 9.0
        elif any(term in description_lower for term in ["single user", "individual", "isolated"]):
            scores["affected_users"] = 2.0
        
        # Discoverability estimation
        if any(term in description_lower for term in ["public", "known", "cve", "disclosed"]):
            scores["discoverability"] = 9.0
        elif any(term in description_lower for term in ["hidden", "obscure", "internal"]):
            scores["discoverability"] = 3.0
        
        # Adjust based on component type
        if component_type == "external_entity":
            scores["exploitability"] += 1.0
        elif component_type == "data_store":
            scores["damage"] += 1.0
        
        # Clamp all values
        return {k: self._clamp(v) for k, v in scores.items()}
    
    def aggregate_scores(
        self,
        threat_scores: List[Dict[str, float]]
    ) -> Dict[str, Any]:
        """
        Aggregate multiple threat scores into an overall assessment.
        
        Args:
            threat_scores: List of DREAD score dictionaries
        
        Returns:
            Aggregated statistics
        """
        if not threat_scores:
            return {
                "count": 0,
                "average_score": 0,
                "max_score": 0,
                "min_score": 0,
                "risk_distribution": {}
            }
        
        scores = [s.get("score", 5.0) for s in threat_scores]
        levels = [s.get("level", "medium") for s in threat_scores]
        
        # Count by risk level
        risk_distribution = {}
        for level in levels:
            risk_distribution[level] = risk_distribution.get(level, 0) + 1
        
        return {
            "count": len(threat_scores),
            "average_score": round(float(np.mean(scores)), 2),
            "max_score": round(float(np.max(scores)), 2),
            "min_score": round(float(np.min(scores)), 2),
            "std_dev": round(float(np.std(scores)), 2),
            "risk_distribution": risk_distribution
        }
    
    def compare_threats(
        self,
        threat_a: Dict[str, float],
        threat_b: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Compare two threats by their DREAD scores.
        
        Args:
            threat_a: First threat's DREAD scores
            threat_b: Second threat's DREAD scores
        
        Returns:
            Comparison result
        """
        score_a = self.calculate_from_dict(threat_a)
        score_b = self.calculate_from_dict(threat_b)
        
        difference = score_a["score"] - score_b["score"]
        
        return {
            "threat_a_score": score_a["score"],
            "threat_b_score": score_b["score"],
            "difference": round(difference, 2),
            "higher_risk": "A" if difference > 0 else "B" if difference < 0 else "Equal",
            "factor_comparison": {
                factor: {
                    "a": threat_a.get(factor, 5),
                    "b": threat_b.get(factor, 5),
                    "diff": round(threat_a.get(factor, 5) - threat_b.get(factor, 5), 2)
                }
                for factor in ["damage", "reproducibility", "exploitability", 
                              "affected_users", "discoverability"]
            }
        }


