"""
Guardrail Agent
Validates outputs and prevents hallucination
"""

from typing import Dict, Any, List, Optional
import json

import structlog

from app.services.llm_provider import LLMProvider

logger = structlog.get_logger()


class GuardrailAgent:
    """
    Guardrail Agent for output validation and quality assurance.
    
    Responsibilities:
    - Validate threat findings
    - Prevent hallucination
    - Ensure consistency with standards
    - Check compliance accuracy
    """
    
    VALID_STRIDE_CATEGORIES = [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege"
    ]
    
    VALID_SEVERITIES = ["low", "medium", "high", "critical"]
    
    VALID_NIST_FAMILIES = ["AC", "AU", "IA", "SC", "SI", "AT", "CA", "CM", "CP", "IR", "MA", "MP", "PE", "PL", "PS", "RA", "SA", "PM"]
    
    def __init__(self, llm: LLMProvider):
        self.llm = llm
    
    async def run(
        self,
        threat_results: Dict[str, Any],
        compliance_results: Dict[str, Any],
        devsecops_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate all analysis outputs.
        
        Args:
            threat_results: Results from threat agent
            compliance_results: Results from compliance agent
            devsecops_results: Results from DevSecOps agent
        
        Returns:
            Validation results with warnings
        """
        logger.info("Running guardrail validation")
        
        warnings = []
        corrections = []
        
        # Validate threats
        threat_validation = self._validate_threats(threat_results.get("threats", []))
        warnings.extend(threat_validation["warnings"])
        corrections.extend(threat_validation["corrections"])
        
        # Validate compliance mappings
        compliance_validation = self._validate_compliance(compliance_results)
        warnings.extend(compliance_validation["warnings"])
        
        # Validate DevSecOps rules
        devsecops_validation = self._validate_devsecops(devsecops_results)
        warnings.extend(devsecops_validation["warnings"])
        
        # Check for potential hallucination
        hallucination_check = await self._check_hallucination(
            threat_results,
            compliance_results
        )
        warnings.extend(hallucination_check["warnings"])
        
        validated = len(warnings) == 0
        
        logger.info("Guardrail validation complete",
                   validated=validated,
                   warnings=len(warnings),
                   corrections=len(corrections))
        
        return {
            "validated": validated,
            "warnings": warnings,
            "corrections": corrections,
            "validation_details": {
                "threats": threat_validation,
                "compliance": compliance_validation,
                "devsecops": devsecops_validation,
                "hallucination_check": hallucination_check
            }
        }
    
    def _validate_threats(
        self,
        threats: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate threat findings"""
        warnings = []
        corrections = []
        
        for idx, threat in enumerate(threats):
            threat_id = threat.get("id", f"threat_{idx}")
            
            # Validate STRIDE category
            category = threat.get("category", "")
            if category not in self.VALID_STRIDE_CATEGORIES:
                warnings.append(f"Invalid STRIDE category for {threat_id}: {category}")
                # Find closest match
                closest = self._find_closest_category(category)
                if closest:
                    corrections.append({
                        "threat_id": threat_id,
                        "field": "category",
                        "original": category,
                        "corrected": closest
                    })
            
            # Validate severity
            severity = threat.get("severity", "").lower()
            if severity not in self.VALID_SEVERITIES:
                warnings.append(f"Invalid severity for {threat_id}: {severity}")
            
            # Validate DREAD scores
            dread_score = threat.get("dread_score", {})
            for metric, value in dread_score.items():
                if not isinstance(value, (int, float)) or value < 1 or value > 10:
                    warnings.append(f"Invalid DREAD {metric} for {threat_id}: {value}")
            
            # Validate risk score
            risk = threat.get("overall_risk", 0)
            if not isinstance(risk, (int, float)) or risk < 0 or risk > 10:
                warnings.append(f"Invalid risk score for {threat_id}: {risk}")
            
            # Validate mitigations exist
            mitigations = threat.get("mitigations", [])
            if not mitigations:
                warnings.append(f"No mitigations provided for {threat_id}")
            
            # Check for generic/vague descriptions
            description = threat.get("description", "")
            if len(description) < 20:
                warnings.append(f"Description too short for {threat_id}")
        
        return {
            "valid": len(warnings) == 0,
            "warnings": warnings,
            "corrections": corrections,
            "threats_validated": len(threats)
        }
    
    def _validate_compliance(
        self,
        compliance_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate compliance mappings"""
        warnings = []
        
        # Validate NIST controls
        nist_controls = compliance_results.get("nist_800_53", {}).get("controls", [])
        for control in nist_controls:
            family = control.split("-")[0] if "-" in control else control[:2]
            if family not in self.VALID_NIST_FAMILIES:
                warnings.append(f"Invalid NIST family: {family} in control {control}")
        
        # Validate ASVS controls
        asvs_controls = compliance_results.get("owasp_asvs", {}).get("controls", [])
        for control in asvs_controls:
            if not control.startswith("V") and not control[0].isdigit():
                warnings.append(f"Invalid ASVS control format: {control}")
        
        # Check for reasonable coverage
        if len(nist_controls) == 0 and len(asvs_controls) == 0:
            warnings.append("No compliance controls identified - may indicate incomplete analysis")
        
        return {
            "valid": len(warnings) == 0,
            "warnings": warnings,
            "nist_controls_validated": len(nist_controls),
            "asvs_controls_validated": len(asvs_controls)
        }
    
    def _validate_devsecops(
        self,
        devsecops_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate DevSecOps rules"""
        warnings = []
        
        # Validate Checkov rules
        checkov_rules = devsecops_results.get("checkov", {}).get("custom_policies", [])
        for rule in checkov_rules:
            if not rule.get("id") or not rule.get("id").startswith("CKV"):
                warnings.append(f"Invalid Checkov rule ID: {rule.get('id')}")
        
        # Validate tfsec rules
        tfsec_rules = devsecops_results.get("tfsec", {}).get("custom_rules", [])
        for rule in tfsec_rules:
            if not rule.get("description"):
                warnings.append(f"tfsec rule missing description: {rule.get('id')}")
        
        # Validate Semgrep rules
        semgrep_rules = devsecops_results.get("semgrep", {}).get("rules", [])
        for rule in semgrep_rules:
            if not rule.get("patterns") and not rule.get("pattern"):
                warnings.append(f"Semgrep rule missing pattern: {rule.get('id')}")
        
        return {
            "valid": len(warnings) == 0,
            "warnings": warnings,
            "rules_validated": {
                "checkov": len(checkov_rules),
                "tfsec": len(tfsec_rules),
                "semgrep": len(semgrep_rules)
            }
        }
    
    async def _check_hallucination(
        self,
        threat_results: Dict[str, Any],
        compliance_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for potential hallucination in outputs"""
        warnings = []
        
        threats = threat_results.get("threats", [])
        
        # Check for unrealistic threat counts
        if len(threats) > 50:
            warnings.append("Unusually high number of threats - may include false positives")
        
        # Check for duplicate threats
        titles = [t.get("title", "") for t in threats]
        unique_titles = set(titles)
        if len(titles) != len(unique_titles):
            warnings.append("Duplicate threat titles detected")
        
        # Check for all same severity
        severities = set(t.get("severity", "") for t in threats)
        if len(threats) > 3 and len(severities) == 1:
            warnings.append("All threats have same severity - may indicate templated output")
        
        # Check for overly specific claims without evidence
        for threat in threats:
            description = threat.get("description", "")
            if any(phrase in description.lower() for phrase in ["100%", "definitely", "always", "never"]):
                warnings.append(f"Potentially overconfident claim in threat: {threat.get('id')}")
        
        return {
            "passed": len(warnings) == 0,
            "warnings": warnings,
            "checks_performed": [
                "duplicate_detection",
                "severity_distribution",
                "overconfidence_check",
                "count_validation"
            ]
        }
    
    def _find_closest_category(self, category: str) -> Optional[str]:
        """Find closest valid STRIDE category"""
        category_lower = category.lower()
        
        for valid in self.VALID_STRIDE_CATEGORIES:
            if valid.lower() in category_lower or category_lower in valid.lower():
                return valid
        
        # Map common variations
        variations = {
            "spoof": "Spoofing",
            "tamper": "Tampering",
            "repudi": "Repudiation",
            "info": "Information Disclosure",
            "dos": "Denial of Service",
            "priv": "Elevation of Privilege",
            "elev": "Elevation of Privilege"
        }
        
        for key, value in variations.items():
            if key in category_lower:
                return value
        
        return None


