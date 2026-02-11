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
    """Represents a STRIDE threat with enhanced schema"""
    category: STRIDECategory
    description: str
    affected_property: str
    typical_mitigations: List[str]
    examples: List[str]
    # Enhanced fields for scenario-driven threat modeling
    scenario: str = ""  # PadmaVue.ai-specific attack narrative
    specific_mitigations: List[str] = None  # Technical, prescriptive fixes
    references: List[str] = None  # OWASP/CWE markdown links
    
    def __post_init__(self):
        if self.specific_mitigations is None:
            self.specific_mitigations = []
        if self.references is None:
            self.references = []


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
            ],
            scenario="An attacker intercepts a valid JWT from the PadmaVue.ai /api/auth/login response using a MITM attack on an unsecured network. They decode the token, modify the 'role' claim from 'user' to 'admin', and re-sign it with a weak HS256 secret obtained from a misconfigured .env file exposed via directory traversal. With the forged token, they access /api/admin/settings and disable security logging.",
            specific_mitigations=[
                "Use RS256 asymmetric JWT signing instead of HS256 symmetric",
                "Store JWT secrets in AWS Secrets Manager or HashiCorp Vault, never in .env files",
                "Implement token binding to client fingerprint (IP + User-Agent hash)",
                "Set short token expiration (15min access tokens, 7-day refresh with rotation)",
                "Enable MFA via TOTP (Google Authenticator) for all admin accounts"
            ],
            references=[
                "[OWASP A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)",
                "[CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)",
                "[CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)"
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
            ],
            scenario="An attacker submits the payload `'; UPDATE users SET role='admin' WHERE username='attacker';--` into the PadmaVue.ai 'Search threats' input field. The backend concatenates this input directly into a SQL query without parameterization, allowing the attacker to escalate their privileges to admin. They then modify threat severity scores to hide critical vulnerabilities from the exported reports.",
            specific_mitigations=[
                "Use SQLAlchemy ORM with bound parameters exclusively (no raw SQL queries)",
                "Validate all search inputs against allowlist regex: ^[a-zA-Z0-9\\s\\-_]+$",
                "Implement Content-Security-Policy header with script-src 'self' to block XSS",
                "Enable PostgreSQL query logging for injection attempt forensics",
                "Deploy AWS WAF or Cloudflare WAF with OWASP CRS 3.x ruleset"
            ],
            references=[
                "[OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)",
                "[CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)",
                "[CWE-79: Cross-site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)"
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
            ],
            scenario="A malicious insider with database access exports all threat intelligence data via the /api/export endpoint, including proprietary STRIDE and PASTA analysis results. They then connect to the PostgreSQL database directly and execute `DELETE FROM audit_logs WHERE user_id='insider_id'` to remove evidence of their actions. Without tamper-evident logging, the data theft goes undetected until customers report seeing their threat models on a competitor's platform.",
            specific_mitigations=[
                "Ship logs to immutable storage (AWS CloudWatch Logs with retention lock or S3 Object Lock)",
                "Implement cryptographic log signing using ed25519 signatures per log entry",
                "Use separate database credentials for audit log writes (append-only, no DELETE permission)",
                "Enable row-level security in PostgreSQL with audit triggers on sensitive tables",
                "Set up real-time alerting via PagerDuty/Opsgenie for bulk export operations"
            ],
            references=[
                "[OWASP A09:2021 - Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)",
                "[CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)",
                "[CWE-779: Logging of Excessive Data](https://cwe.mitre.org/data/definitions/779.html)"
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
            ],
            scenario="An attacker sends a malformed JSON payload `{\"project_id\": null, \"__proto__\": {\"admin\": true}}` to the /api/analyze endpoint. The FastAPI backend raises an unhandled exception, and with DEBUG=True still enabled in production, the full Python traceback is returned to the client. The traceback reveals the DATABASE_URL containing PostgreSQL credentials, the OPENAI_API_KEY, and internal file paths showing the deployment structure.",
            specific_mitigations=[
                "Set DEBUG=False and configure custom error handlers returning only error codes (no stack traces)",
                "Use python-dotenv with .env files excluded from Docker images via .dockerignore",
                "Implement structured JSON error responses: {\"error\": \"code\", \"request_id\": \"uuid\"} only",
                "Enable TLS 1.3 for all API endpoints with HSTS header (max-age=31536000)",
                "Encrypt sensitive fields in database using application-level encryption (AWS KMS or age)"
            ],
            references=[
                "[OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)",
                "[CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)",
                "[CWE-209: Error Message Information Leak](https://cwe.mitre.org/data/definitions/209.html)"
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
            ],
            scenario="An attacker scripts 10,000 concurrent POST requests to /api/analyze, each uploading a 50MB malformed PDF document. The FastAPI worker pool (4 Uvicorn workers) becomes saturated processing the uploads. Simultaneously, the attacker sends ReDoS payloads to the search endpoint with patterns like `(a+)+$` that cause exponential regex backtracking. Within 60 seconds, all workers are blocked, memory usage spikes to 95%, and legitimate users receive 503 Service Unavailable errors.",
            specific_mitigations=[
                "Implement rate limiting: 100 requests/minute per IP using FastAPI-Limiter with Redis backend",
                "Set maximum upload size to 10MB via nginx client_max_body_size directive",
                "Use non-backtracking regex or RE2 library for user-supplied pattern matching",
                "Deploy behind Cloudflare or AWS Shield for volumetric DDoS protection",
                "Configure Uvicorn with --limit-concurrency 100 and --timeout-keep-alive 5"
            ],
            references=[
                "[OWASP - Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)",
                "[CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)",
                "[CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)"
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
            ],
            scenario="A standard user discovers that PadmaVue.ai stores their role in localStorage as `{\"userRole\": \"user\"}`. Using browser DevTools, they modify this to `{\"userRole\": \"admin\"}` and refresh the page. The React frontend now renders admin UI components. When they access /api/admin/users, the backend trusts the role from the JWT without server-side verification, granting them access to view all users, modify threat models, and delete projects belonging to other organizations.",
            specific_mitigations=[
                "Validate user roles server-side on EVERY request using JWT claims verified against database",
                "Implement RBAC middleware that denies by default: @require_role(['admin']) decorator",
                "Never trust client-side role storage; treat localStorage/sessionStorage as attacker-controlled",
                "Use signed JWTs with RS256 where role claims cannot be modified without private key",
                "Implement organization-scoped access: users can only access resources where org_id matches"
            ],
            references=[
                "[OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)",
                "[CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)",
                "[CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)"
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
            List of potential threats with mitigations and enhanced fields
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
                "examples": threat_info.examples,
                # Enhanced fields
                "scenario": threat_info.scenario,
                "specific_mitigations": threat_info.specific_mitigations,
                "references": threat_info.references
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
    
    def get_references(self, category: STRIDECategory) -> List[str]:
        """Get OWASP/CWE references for a STRIDE category"""
        threat = self.STRIDE_DEFINITIONS.get(category)
        return threat.references if threat else []
    
    def get_scenario(self, category: STRIDECategory) -> str:
        """Get PadmaVue.ai-specific attack scenario for a STRIDE category"""
        threat = self.STRIDE_DEFINITIONS.get(category)
        return threat.scenario if threat else ""
    
    def get_specific_mitigations(self, category: STRIDECategory) -> List[str]:
        """Get technical, prescriptive mitigations for a STRIDE category"""
        threat = self.STRIDE_DEFINITIONS.get(category)
        return threat.specific_mitigations if threat else []
    
    def get_stride_summary(self) -> Dict[str, Any]:
        """Get a summary of the STRIDE methodology with enhanced fields"""
        return {
            "name": "STRIDE",
            "description": "Threat modeling methodology developed by Microsoft",
            "categories": [
                {
                    "name": cat.value,
                    "initial": cat.value[0],
                    "description": self.STRIDE_DEFINITIONS[cat].description,
                    "affected_property": self.STRIDE_DEFINITIONS[cat].affected_property,
                    "scenario": self.STRIDE_DEFINITIONS[cat].scenario,
                    "specific_mitigations": self.STRIDE_DEFINITIONS[cat].specific_mitigations,
                    "references": self.STRIDE_DEFINITIONS[cat].references
                }
                for cat in STRIDECategory
            ],
            "usage": "Apply to each component and data flow in the system to identify threats"
        }


