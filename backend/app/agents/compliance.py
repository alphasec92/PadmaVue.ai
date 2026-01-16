"""
Compliance Agent
Maps threats to NIST 800-53 and OWASP ASVS controls
"""

from typing import Dict, Any, List, Optional
import json

import structlog

from app.services.llm_provider import LLMProvider
from app.engines.compliance_mapper import ComplianceMapper

logger = structlog.get_logger()


class ComplianceAgent:
    """
    Compliance Agent for mapping threats to security controls.
    
    Supported Frameworks:
    - NIST 800-53 Rev 5 (AC, AU, IA, SC, SI families)
    - OWASP ASVS (Application Security Verification Standard)
    """
    
    SYSTEM_PROMPT = """You are a Security Compliance Agent specialized in mapping 
security threats to compliance frameworks and controls.

Your expertise includes:
- NIST 800-53 Rev 5 security controls
- OWASP ASVS requirements
- Security control implementation guidance
- Gap analysis and remediation prioritization

When mapping threats to controls, consider:
1. Direct control applicability
2. Implementation priority
3. Control effectiveness
4. Compliance gaps

Provide specific, actionable mappings with control IDs."""
    
    def __init__(self, llm: LLMProvider):
        self.llm = llm
        self.compliance_mapper = ComplianceMapper()
    
    async def run(
        self,
        threat_results: Dict[str, Any],
        frameworks: List[str] = None
    ) -> Dict[str, Any]:
        """
        Map threats to compliance controls.
        
        Args:
            threat_results: Results from threat agent
            frameworks: List of frameworks to map
        
        Returns:
            Compliance mapping results
        """
        if frameworks is None:
            frameworks = ["NIST_800_53", "OWASP_ASVS"]
        
        logger.info("Running compliance mapping", frameworks=frameworks)
        
        threats = threat_results.get("threats", [])
        
        # Map each threat to controls
        mapped_threats = []
        all_controls = {"NIST_800_53": set(), "OWASP_ASVS": set()}
        
        for threat in threats:
            # Get mappings from compliance mapper
            nist_controls = self.compliance_mapper.map_to_nist(
                threat.get("category", ""),
                threat.get("mitigations", [])
            )
            
            asvs_controls = self.compliance_mapper.map_to_asvs(
                threat.get("category", ""),
                threat.get("mitigations", [])
            )
            
            # Update threat with mappings
            threat["compliance_mappings"] = {
                "NIST_800_53": nist_controls,
                "OWASP_ASVS": asvs_controls
            }
            
            mapped_threats.append(threat)
            
            # Collect all controls
            all_controls["NIST_800_53"].update(nist_controls)
            all_controls["OWASP_ASVS"].update(asvs_controls)
        
        # Generate compliance summary
        summary = await self._generate_summary(
            mapped_threats,
            all_controls,
            frameworks
        )
        
        logger.info("Compliance mapping complete",
                   nist_controls=len(all_controls["NIST_800_53"]),
                   asvs_controls=len(all_controls["OWASP_ASVS"]))
        
        return {
            "mapped_threats": mapped_threats,
            "overall_score": summary.get("overall_score", 0),
            "nist_800_53": {
                "controls": list(all_controls["NIST_800_53"]),
                "by_family": self._group_nist_by_family(all_controls["NIST_800_53"]),
                "coverage": summary.get("nist_coverage", {})
            },
            "owasp_asvs": {
                "controls": list(all_controls["OWASP_ASVS"]),
                "by_chapter": self._group_asvs_by_chapter(all_controls["OWASP_ASVS"]),
                "coverage": summary.get("asvs_coverage", {})
            },
            "gaps": summary.get("gaps", []),
            "priorities": summary.get("priorities", [])
        }
    
    async def _generate_summary(
        self,
        threats: List[Dict[str, Any]],
        all_controls: Dict[str, set],
        frameworks: List[str]
    ) -> Dict[str, Any]:
        """Generate compliance summary using LLM"""
        # Build context
        threat_summaries = []
        for t in threats[:10]:  # Limit to top 10
            threat_summaries.append({
                "category": t.get("category"),
                "title": t.get("title"),
                "severity": t.get("severity"),
                "nist_controls": t.get("compliance_mappings", {}).get("NIST_800_53", []),
                "asvs_controls": t.get("compliance_mappings", {}).get("OWASP_ASVS", [])
            })
        
        prompt = f"""Analyze the following threat-to-control mappings and provide a compliance summary.

## Threats and Controls
{json.dumps(threat_summaries, indent=2)}

## Required Analysis
1. Overall compliance score (0-100)
2. NIST 800-53 coverage assessment
3. OWASP ASVS coverage assessment
4. Compliance gaps identified
5. Remediation priorities

Respond with JSON:
{{
    "overall_score": 75,
    "nist_coverage": {{"AC": "partial", "AU": "full", "IA": "minimal"}},
    "asvs_coverage": {{"V2": "full", "V3": "partial"}},
    "gaps": ["gap1", "gap2"],
    "priorities": ["priority1", "priority2"]
}}"""
        
        try:
            response = await self.llm.generate(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temp=0.3
            )
            
            # Parse response
            start = response.find("{")
            end = response.rfind("}") + 1
            
            if start >= 0 and end > start:
                return json.loads(response[start:end])
                
        except Exception as e:
            logger.error("Summary generation failed", error=str(e))
        
        # Return default summary
        return self._get_default_summary(threats)
    
    def _group_nist_by_family(self, controls: set) -> Dict[str, List[str]]:
        """Group NIST controls by family"""
        families = {
            "AC": [],  # Access Control
            "AU": [],  # Audit and Accountability
            "IA": [],  # Identification and Authentication
            "SC": [],  # System and Communications Protection
            "SI": []   # System and Information Integrity
        }
        
        for control in controls:
            family = control.split("-")[0] if "-" in control else control[:2]
            if family in families:
                families[family].append(control)
        
        return {k: v for k, v in families.items() if v}
    
    def _group_asvs_by_chapter(self, controls: set) -> Dict[str, List[str]]:
        """Group ASVS controls by chapter"""
        chapters = {
            "V1": [],   # Architecture
            "V2": [],   # Authentication
            "V3": [],   # Session Management
            "V4": [],   # Access Control
            "V5": [],   # Validation
            "V6": [],   # Stored Cryptography
            "V7": [],   # Error Handling
            "V8": [],   # Data Protection
            "V9": [],   # Communication
            "V10": [],  # Malicious Code
            "V11": [],  # Business Logic
            "V12": [],  # Files and Resources
            "V13": [],  # API
            "V14": []   # Configuration
        }
        
        for control in controls:
            chapter = control.split(".")[0] if "." in control else control[:2]
            if chapter in chapters:
                chapters[chapter].append(control)
        
        return {k: v for k, v in chapters.items() if v}
    
    def _get_default_summary(self, threats: List[Dict]) -> Dict[str, Any]:
        """Return default compliance summary"""
        threat_count = len(threats)
        
        return {
            "overall_score": max(100 - (threat_count * 5), 50),
            "nist_coverage": {
                "AC": "partial",
                "AU": "partial",
                "IA": "partial",
                "SC": "minimal",
                "SI": "minimal"
            },
            "asvs_coverage": {
                "V2": "partial",
                "V3": "partial",
                "V4": "partial",
                "V5": "minimal"
            },
            "gaps": [
                "Encryption at rest not fully implemented",
                "Audit logging coverage incomplete",
                "Multi-factor authentication not enforced",
                "Input validation gaps identified",
                "Session management needs improvement"
            ],
            "priorities": [
                "1. Implement comprehensive input validation (NIST SI-10, ASVS V5)",
                "2. Enable MFA for privileged accounts (NIST IA-2, ASVS V2)",
                "3. Enhance audit logging coverage (NIST AU-2, ASVS V7)",
                "4. Deploy encryption for sensitive data (NIST SC-28, ASVS V6)",
                "5. Strengthen access controls (NIST AC-3, ASVS V4)"
            ]
        }


