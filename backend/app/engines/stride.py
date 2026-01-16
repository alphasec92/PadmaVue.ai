"""
STRIDE Threat Modeling Engine
Implements the STRIDE methodology for threat identification
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass


class STRIDECategory(str, Enum):
    """STRIDE threat categories"""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class STRIDEThreat:
    """Represents a STRIDE threat"""
    category: STRIDECategory
    description: str
    affected_property: str
    typical_mitigations: List[str]
    examples: List[str]


class STRIDEEngine:
    """
    STRIDE Threat Modeling Engine.
    
    STRIDE is a threat modeling methodology developed by Microsoft:
    - Spoofing: Pretending to be something or someone else
    - Tampering: Modifying data or code
    - Repudiation: Denying having performed an action
    - Information Disclosure: Exposing information to unauthorized parties
    - Denial of Service: Making a system unavailable
    - Elevation of Privilege: Gaining capabilities without authorization
    """
    
    STRIDE_DEFINITIONS: Dict[STRIDECategory, STRIDEThreat] = {
        STRIDECategory.SPOOFING: STRIDEThreat(
            category=STRIDECategory.SPOOFING,
            description="Identity threats - pretending to be something or someone you're not",
            affected_property="Authentication",
            typical_mitigations=[
                "Implement strong authentication mechanisms",
                "Use multi-factor authentication (MFA)",
                "Validate and verify identities",
                "Implement certificate-based authentication",
                "Use secure token management"
            ],
            examples=[
                "Session hijacking",
                "Token forgery",
                "Credential theft",
                "Man-in-the-middle attacks",
                "Phishing attacks"
            ]
        ),
        STRIDECategory.TAMPERING: STRIDEThreat(
            category=STRIDECategory.TAMPERING,
            description="Data integrity threats - unauthorized modification of data or code",
            affected_property="Integrity",
            typical_mitigations=[
                "Implement input validation and sanitization",
                "Use parameterized queries",
                "Apply digital signatures",
                "Implement integrity checking",
                "Use write-once storage for critical data"
            ],
            examples=[
                "SQL injection",
                "Cross-site scripting (XSS)",
                "Parameter tampering",
                "Cookie manipulation",
                "Binary patching"
            ]
        ),
        STRIDECategory.REPUDIATION: STRIDEThreat(
            category=STRIDECategory.REPUDIATION,
            description="Audit threats - ability to deny having performed an action",
            affected_property="Non-repudiation",
            typical_mitigations=[
                "Implement comprehensive logging",
                "Use secure audit trails",
                "Apply digital signatures for transactions",
                "Implement tamper-evident logs",
                "Store logs in write-once storage"
            ],
            examples=[
                "Denying a transaction occurred",
                "Log tampering",
                "Timestamp manipulation",
                "Audit trail deletion"
            ]
        ),
        STRIDECategory.INFORMATION_DISCLOSURE: STRIDEThreat(
            category=STRIDECategory.INFORMATION_DISCLOSURE,
            description="Confidentiality threats - exposing information to unauthorized parties",
            affected_property="Confidentiality",
            typical_mitigations=[
                "Encrypt data at rest and in transit",
                "Implement proper access controls",
                "Apply data masking and tokenization",
                "Use secure error handling",
                "Implement data classification"
            ],
            examples=[
                "Data breaches",
                "Information leakage in errors",
                "Directory traversal",
                "Eavesdropping",
                "Memory dumps"
            ]
        ),
        STRIDECategory.DENIAL_OF_SERVICE: STRIDEThreat(
            category=STRIDECategory.DENIAL_OF_SERVICE,
            description="Availability threats - making a system or service unavailable",
            affected_property="Availability",
            typical_mitigations=[
                "Implement rate limiting",
                "Use load balancing",
                "Apply resource quotas",
                "Implement DDoS protection",
                "Design for graceful degradation"
            ],
            examples=[
                "DDoS attacks",
                "Resource exhaustion",
                "Application-level DoS",
                "Algorithmic complexity attacks",
                "Connection pool exhaustion"
            ]
        ),
        STRIDECategory.ELEVATION_OF_PRIVILEGE: STRIDEThreat(
            category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
            description="Authorization threats - gaining capabilities without proper authorization",
            affected_property="Authorization",
            typical_mitigations=[
                "Implement least privilege principle",
                "Use role-based access control (RBAC)",
                "Validate authorization on every request",
                "Implement proper privilege separation",
                "Regular access reviews"
            ],
            examples=[
                "Privilege escalation",
                "IDOR vulnerabilities",
                "Insecure direct object references",
                "Role manipulation",
                "Permission bypass"
            ]
        )
    }
    
    # Mapping of component types to likely STRIDE threats
    COMPONENT_THREAT_MAP = {
        "external_entity": [
            STRIDECategory.SPOOFING,
            STRIDECategory.REPUDIATION
        ],
        "process": [
            STRIDECategory.SPOOFING,
            STRIDECategory.TAMPERING,
            STRIDECategory.REPUDIATION,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE,
            STRIDECategory.ELEVATION_OF_PRIVILEGE
        ],
        "data_store": [
            STRIDECategory.TAMPERING,
            STRIDECategory.REPUDIATION,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE
        ],
        "data_flow": [
            STRIDECategory.TAMPERING,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE
        ]
    }
    
    def __init__(self):
        pass
    
    def get_category_info(self, category: STRIDECategory) -> STRIDEThreat:
        """Get detailed information about a STRIDE category"""
        return self.STRIDE_DEFINITIONS.get(category)
    
    def get_all_categories(self) -> List[STRIDECategory]:
        """Get all STRIDE categories"""
        return list(STRIDECategory)
    
    def get_threats_for_component(
        self,
        component_type: str
    ) -> List[STRIDECategory]:
        """Get applicable STRIDE categories for a component type"""
        return self.COMPONENT_THREAT_MAP.get(
            component_type.lower(),
            list(STRIDECategory)  # Default to all if unknown
        )
    
    def get_mitigations(
        self,
        category: STRIDECategory
    ) -> List[str]:
        """Get recommended mitigations for a STRIDE category"""
        threat = self.STRIDE_DEFINITIONS.get(category)
        return threat.typical_mitigations if threat else []
    
    def analyze_component(
        self,
        component_name: str,
        component_type: str,
        properties: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze a component for STRIDE threats.
        
        Args:
            component_name: Name of the component
            component_type: Type (external_entity, process, data_store, data_flow)
            properties: Additional properties to consider
        
        Returns:
            List of potential threats with mitigations
        """
        threats = []
        applicable_categories = self.get_threats_for_component(component_type)
        
        for category in applicable_categories:
            threat_info = self.STRIDE_DEFINITIONS[category]
            
            threats.append({
                "category": category.value,
                "component": component_name,
                "component_type": component_type,
                "description": f"{threat_info.description} affecting {component_name}",
                "affected_property": threat_info.affected_property,
                "mitigations": threat_info.typical_mitigations,
                "examples": threat_info.examples
            })
        
        return threats
    
    def analyze_data_flow(
        self,
        source: str,
        target: str,
        data_type: str,
        encrypted: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Analyze a data flow for STRIDE threats.
        
        Args:
            source: Source component
            target: Target component
            data_type: Type of data flowing
            encrypted: Whether the flow is encrypted
        
        Returns:
            List of potential threats
        """
        threats = []
        
        # Tampering threat
        tampering_threat = {
            "category": STRIDECategory.TAMPERING.value,
            "flow": f"{source} -> {target}",
            "description": f"Data in transit ({data_type}) could be modified",
            "risk_level": "low" if encrypted else "high",
            "mitigations": [
                "Use TLS/SSL for data in transit",
                "Implement message integrity checks",
                "Use digital signatures for critical data"
            ]
        }
        threats.append(tampering_threat)
        
        # Information Disclosure threat
        disclosure_threat = {
            "category": STRIDECategory.INFORMATION_DISCLOSURE.value,
            "flow": f"{source} -> {target}",
            "description": f"Data ({data_type}) could be intercepted and read",
            "risk_level": "low" if encrypted else "high",
            "mitigations": [
                "Encrypt all data in transit",
                "Use secure protocols (HTTPS, TLS 1.3)",
                "Implement proper key management"
            ]
        }
        threats.append(disclosure_threat)
        
        # DoS threat
        dos_threat = {
            "category": STRIDECategory.DENIAL_OF_SERVICE.value,
            "flow": f"{source} -> {target}",
            "description": "Data flow could be disrupted or flooded",
            "risk_level": "medium",
            "mitigations": [
                "Implement rate limiting",
                "Use connection timeouts",
                "Deploy traffic filtering"
            ]
        }
        threats.append(dos_threat)
        
        return threats
    
    def get_stride_summary(self) -> Dict[str, Any]:
        """Get a summary of the STRIDE methodology"""
        return {
            "name": "STRIDE",
            "description": "Threat modeling methodology developed by Microsoft",
            "categories": [
                {
                    "name": cat.value,
                    "initial": cat.value[0],
                    "description": self.STRIDE_DEFINITIONS[cat].description,
                    "affected_property": self.STRIDE_DEFINITIONS[cat].affected_property
                }
                for cat in STRIDECategory
            ],
            "usage": "Apply to each component and data flow in the system to identify threats"
        }


