"""
Compliance Mapping Engine
Maps threats and mitigations to NIST 800-53 and OWASP ASVS
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass


@dataclass
class NISTControl:
    """NIST 800-53 Control"""
    id: str
    family: str
    title: str
    description: str
    priority: str  # P1, P2, P3


@dataclass
class ASVSRequirement:
    """OWASP ASVS Requirement"""
    id: str
    chapter: str
    title: str
    level: int  # L1, L2, L3


class ComplianceMapper:
    """
    Maps security threats and mitigations to compliance controls.
    
    Supported frameworks:
    - NIST 800-53 Rev 5
    - OWASP ASVS 4.0
    """
    
    # NIST 800-53 Control Mappings by STRIDE Category
    STRIDE_TO_NIST = {
        "Spoofing": {
            "primary": ["IA-2", "IA-5", "IA-8"],
            "secondary": ["AC-3", "AC-17", "SC-8"]
        },
        "Tampering": {
            "primary": ["SI-10", "SI-7", "SC-8"],
            "secondary": ["AU-9", "SC-28", "SI-3"]
        },
        "Repudiation": {
            "primary": ["AU-2", "AU-3", "AU-6"],
            "secondary": ["AU-9", "AU-12", "AC-6"]
        },
        "Information Disclosure": {
            "primary": ["SC-8", "SC-13", "SC-28"],
            "secondary": ["AC-3", "AC-4", "MP-5"]
        },
        "Denial of Service": {
            "primary": ["SC-5", "SC-7", "CP-9"],
            "secondary": ["SI-17", "AC-20", "AU-6"]
        },
        "Elevation of Privilege": {
            "primary": ["AC-3", "AC-6", "AC-2"],
            "secondary": ["CM-7", "SC-2", "SI-7"]
        }
    }
    
    # OWASP ASVS Mappings by STRIDE Category
    STRIDE_TO_ASVS = {
        "Spoofing": {
            "L1": ["V2.1.1", "V2.1.2", "V2.2.1"],
            "L2": ["V2.3.1", "V2.5.1", "V2.7.1"],
            "L3": ["V2.8.1", "V2.9.1", "V2.10.1"]
        },
        "Tampering": {
            "L1": ["V5.1.1", "V5.1.2", "V5.2.1"],
            "L2": ["V5.2.2", "V5.3.1", "V5.3.2"],
            "L3": ["V5.4.1", "V5.5.1", "V5.5.2"]
        },
        "Repudiation": {
            "L1": ["V7.1.1", "V7.1.2"],
            "L2": ["V7.2.1", "V7.2.2", "V7.3.1"],
            "L3": ["V7.4.1", "V7.4.2"]
        },
        "Information Disclosure": {
            "L1": ["V6.1.1", "V8.1.1", "V8.2.1"],
            "L2": ["V6.2.1", "V8.2.2", "V8.3.1"],
            "L3": ["V6.3.1", "V6.4.1", "V8.3.4"]
        },
        "Denial of Service": {
            "L1": ["V11.1.1", "V11.1.2"],
            "L2": ["V11.1.3", "V11.1.4"],
            "L3": ["V11.1.5", "V11.1.6"]
        },
        "Elevation of Privilege": {
            "L1": ["V4.1.1", "V4.1.2", "V4.2.1"],
            "L2": ["V4.2.2", "V4.3.1", "V4.3.2"],
            "L3": ["V4.3.3", "V1.4.1", "V1.4.2"]
        }
    }
    
    # Mitigation keyword to NIST control mapping
    MITIGATION_TO_NIST = {
        "encryption": ["SC-8", "SC-13", "SC-28"],
        "encrypt": ["SC-8", "SC-13", "SC-28"],
        "authentication": ["IA-2", "IA-5", "IA-8"],
        "mfa": ["IA-2(1)", "IA-2(2)"],
        "multi-factor": ["IA-2(1)", "IA-2(2)"],
        "access control": ["AC-3", "AC-6", "AC-2"],
        "authorization": ["AC-3", "AC-6"],
        "logging": ["AU-2", "AU-3", "AU-6"],
        "audit": ["AU-2", "AU-3", "AU-6"],
        "monitoring": ["AU-6", "SI-4", "AU-12"],
        "input validation": ["SI-10", "SI-11"],
        "parameterized": ["SI-10"],
        "rate limit": ["SC-5", "SC-7"],
        "firewall": ["SC-7", "AC-4"],
        "backup": ["CP-9", "CP-10"],
        "patch": ["SI-2", "CM-3"],
        "least privilege": ["AC-6", "CM-7"],
        "rbac": ["AC-2", "AC-3"],
        "token": ["IA-5", "SC-12"],
        "session": ["SC-23", "AC-12"],
        "certificate": ["SC-17", "IA-5"],
        "tls": ["SC-8", "SC-13"],
        "https": ["SC-8", "SC-13"],
        "waf": ["SC-7", "SI-3"],
        "sanitization": ["SI-10", "SI-11"],
        "escaping": ["SI-10"],
        "hash": ["SC-13", "IA-5"]
    }
    
    # NIST Control Family Information
    NIST_FAMILIES = {
        "AC": "Access Control",
        "AU": "Audit and Accountability",
        "IA": "Identification and Authentication",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "AT": "Awareness and Training",
        "CA": "Assessment, Authorization, and Monitoring",
        "CM": "Configuration Management",
        "CP": "Contingency Planning",
        "IR": "Incident Response",
        "MA": "Maintenance",
        "MP": "Media Protection",
        "PE": "Physical and Environmental Protection",
        "PL": "Planning",
        "PS": "Personnel Security",
        "RA": "Risk Assessment",
        "SA": "System and Services Acquisition",
        "PM": "Program Management"
    }
    
    # ASVS Chapter Information
    ASVS_CHAPTERS = {
        "V1": "Architecture, Design, and Threat Modeling",
        "V2": "Authentication",
        "V3": "Session Management",
        "V4": "Access Control",
        "V5": "Validation, Sanitization, and Encoding",
        "V6": "Stored Cryptography",
        "V7": "Error Handling and Logging",
        "V8": "Data Protection",
        "V9": "Communication",
        "V10": "Malicious Code",
        "V11": "Business Logic",
        "V12": "Files and Resources",
        "V13": "API and Web Service",
        "V14": "Configuration"
    }
    
    def __init__(self):
        pass
    
    def map_to_nist(
        self,
        stride_category: str,
        mitigations: List[str]
    ) -> List[str]:
        """
        Map a threat to NIST 800-53 controls.
        
        Args:
            stride_category: STRIDE category
            mitigations: List of mitigation descriptions
        
        Returns:
            List of applicable NIST controls
        """
        controls: Set[str] = set()
        
        # Add primary controls for STRIDE category
        category_mapping = self.STRIDE_TO_NIST.get(stride_category, {})
        controls.update(category_mapping.get("primary", []))
        controls.update(category_mapping.get("secondary", []))
        
        # Add controls based on mitigation keywords
        for mitigation in mitigations:
            mitigation_lower = mitigation.lower()
            for keyword, nist_controls in self.MITIGATION_TO_NIST.items():
                if keyword in mitigation_lower:
                    controls.update(nist_controls)
        
        return sorted(list(controls))
    
    def map_to_asvs(
        self,
        stride_category: str,
        mitigations: List[str],
        level: int = 2
    ) -> List[str]:
        """
        Map a threat to OWASP ASVS requirements.
        
        Args:
            stride_category: STRIDE category
            mitigations: List of mitigation descriptions
            level: ASVS level (1, 2, or 3)
        
        Returns:
            List of applicable ASVS requirements
        """
        requirements: Set[str] = set()
        
        # Add requirements for STRIDE category up to specified level
        category_mapping = self.STRIDE_TO_ASVS.get(stride_category, {})
        
        for lvl in range(1, level + 1):
            level_key = f"L{lvl}"
            requirements.update(category_mapping.get(level_key, []))
        
        return sorted(list(requirements))
    
    def get_nist_control_info(self, control_id: str) -> Dict[str, str]:
        """Get information about a NIST control"""
        family = control_id.split("-")[0] if "-" in control_id else control_id[:2]
        
        return {
            "id": control_id,
            "family": family,
            "family_name": self.NIST_FAMILIES.get(family, "Unknown"),
            "url": f"https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        }
    
    def get_asvs_requirement_info(self, requirement_id: str) -> Dict[str, str]:
        """Get information about an ASVS requirement"""
        chapter = requirement_id.split(".")[0] if "." in requirement_id else requirement_id[:2]
        
        return {
            "id": requirement_id,
            "chapter": chapter,
            "chapter_name": self.ASVS_CHAPTERS.get(chapter, "Unknown"),
            "url": f"https://owasp.org/www-project-application-security-verification-standard/"
        }
    
    def get_comprehensive_mapping(
        self,
        stride_category: str,
        mitigations: List[str],
        asvs_level: int = 2
    ) -> Dict[str, Any]:
        """
        Get comprehensive compliance mapping for a threat.
        
        Args:
            stride_category: STRIDE category
            mitigations: List of mitigation descriptions
            asvs_level: ASVS verification level
        
        Returns:
            Complete compliance mapping with details
        """
        nist_controls = self.map_to_nist(stride_category, mitigations)
        asvs_requirements = self.map_to_asvs(stride_category, mitigations, asvs_level)
        
        return {
            "nist_800_53": {
                "controls": nist_controls,
                "details": [self.get_nist_control_info(c) for c in nist_controls],
                "families_covered": list(set(c.split("-")[0] for c in nist_controls if "-" in c))
            },
            "owasp_asvs": {
                "requirements": asvs_requirements,
                "details": [self.get_asvs_requirement_info(r) for r in asvs_requirements],
                "chapters_covered": list(set(r.split(".")[0] for r in asvs_requirements if "." in r)),
                "level": asvs_level
            }
        }
    
    def identify_gaps(
        self,
        current_controls: List[str],
        required_controls: List[str]
    ) -> Dict[str, Any]:
        """
        Identify compliance gaps.
        
        Args:
            current_controls: Currently implemented controls
            required_controls: Required controls based on threats
        
        Returns:
            Gap analysis
        """
        current_set = set(current_controls)
        required_set = set(required_controls)
        
        missing = required_set - current_set
        implemented = required_set & current_set
        extra = current_set - required_set
        
        return {
            "missing_controls": sorted(list(missing)),
            "implemented_controls": sorted(list(implemented)),
            "extra_controls": sorted(list(extra)),
            "coverage_percentage": round(
                len(implemented) / len(required_set) * 100 if required_set else 100,
                2
            ),
            "gap_count": len(missing)
        }
    
    def prioritize_remediations(
        self,
        gaps: List[str],
        threat_severities: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Prioritize remediation based on threat severity.
        
        Args:
            gaps: List of missing controls
            threat_severities: Mapping of controls to threat severity
        
        Returns:
            Prioritized list of remediations
        """
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        
        remediations = []
        for control in gaps:
            severity = threat_severities.get(control, "medium")
            remediations.append({
                "control": control,
                "severity": severity,
                "priority": priority_order.get(severity, 2),
                "info": self.get_nist_control_info(control) if control.startswith(tuple(self.NIST_FAMILIES.keys())) else self.get_asvs_requirement_info(control)
            })
        
        # Sort by priority
        remediations.sort(key=lambda x: x["priority"])
        
        # Add priority ranking
        for idx, rem in enumerate(remediations, 1):
            rem["rank"] = idx
        
        return remediations


