"""
OWASP Security Frameworks Mapper
Maps threats to OWASP Top 10 categories including:
- OWASP Top 10 Web Application Security Risks
- OWASP API Security Top 10
- OWASP LLM AI Top 10 (for AI/ML applications)
- OWASP Machine Learning Security Top 10
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class OWASPThreat:
    """OWASP Threat Definition"""
    id: str
    category: str
    title: str
    description: str
    risk_rating: str  # Critical, High, Medium, Low
    attack_vectors: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


class OWASPMapper:
    """
    Maps security threats to OWASP frameworks and provides
    AI/Agentic AI-specific threat identification.
    
    Supported OWASP Frameworks:
    - OWASP Top 10 (2021)
    - OWASP API Security Top 10 (2023)
    - OWASP LLM AI Top 10 (2025)
    - OWASP Machine Learning Security Top 10
    """
    
    # ===========================================
    # OWASP Top 10 Web Application Security (2021)
    # ===========================================
    OWASP_TOP_10_WEB = {
        "A01:2021": {
            "id": "A01:2021",
            "title": "Broken Access Control",
            "description": "Restrictions on what authenticated users are allowed to do are not properly enforced",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Bypassing access control by modifying URL/HTML/API requests",
                "Viewing/editing someone else's account by providing its identifier",
                "Elevation of privilege (acting as admin while logged in as user)",
                "Metadata manipulation (JWT, cookies, hidden fields)",
                "CORS misconfiguration allowing unauthorized API access"
            ],
            "mitigations": [
                "Deny by default except for public resources",
                "Implement access control mechanisms once and reuse throughout application",
                "Model access controls should enforce record ownership",
                "Disable web server directory listing",
                "Log access control failures and alert administrators",
                "Rate limit API and controller access",
                "Invalidate JWT tokens on the server after logout"
            ],
            "keywords": ["access control", "authorization", "privilege", "idor", "cors", "acl", "rbac"]
        },
        "A02:2021": {
            "id": "A02:2021",
            "title": "Cryptographic Failures",
            "description": "Failures related to cryptography that lead to sensitive data exposure",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Transmitting data in clear text (HTTP, SMTP, FTP)",
                "Using old or weak cryptographic algorithms",
                "Using default or weak crypto keys",
                "Not enforcing encryption (missing HSTS headers)",
                "Not validating server certificates properly"
            ],
            "mitigations": [
                "Classify data processed, stored, or transmitted",
                "Don't store sensitive data unnecessarily",
                "Encrypt all sensitive data at rest",
                "Use strong adaptive salted hashing for passwords (Argon2, bcrypt)",
                "Use authenticated encryption for data-in-transit",
                "Disable caching for responses with sensitive data"
            ],
            "keywords": ["encryption", "crypto", "tls", "ssl", "certificate", "hash", "key management", "pii", "sensitive data"]
        },
        "A03:2021": {
            "id": "A03:2021",
            "title": "Injection",
            "description": "User-supplied data is not validated, filtered, or sanitized by the application",
            "risk_rating": "Critical",
            "attack_vectors": [
                "SQL injection through dynamic queries",
                "NoSQL/ORM injection",
                "LDAP injection",
                "OS command injection",
                "Expression Language (EL) injection",
                "Object Graph Navigation Library (OGNL) injection"
            ],
            "mitigations": [
                "Use safe API that avoids using interpreter entirely",
                "Use positive server-side input validation",
                "Escape special characters using interpreter-specific syntax",
                "Use LIMIT and other SQL controls to prevent mass disclosure",
                "Use parameterized queries and stored procedures"
            ],
            "keywords": ["injection", "sql", "xss", "command", "ldap", "xpath", "nosql", "ognl"]
        },
        "A04:2021": {
            "id": "A04:2021",
            "title": "Insecure Design",
            "description": "Missing or ineffective security controls design, different from implementation flaws",
            "risk_rating": "High",
            "attack_vectors": [
                "Missing threat modeling during design",
                "No secure design patterns",
                "Insufficient segregation of tenants in multi-tenant architecture",
                "Missing rate limiting in critical operations"
            ],
            "mitigations": [
                "Establish secure development lifecycle with AppSec professionals",
                "Use threat modeling for critical authentication, access control, and business logic",
                "Integrate security language and controls into user stories",
                "Use tiered layer of defense",
                "Limit resource consumption by user or service"
            ],
            "keywords": ["design", "architecture", "threat model", "multi-tenant", "segregation"]
        },
        "A05:2021": {
            "id": "A05:2021",
            "title": "Security Misconfiguration",
            "description": "Missing appropriate security hardening or improperly configured permissions",
            "risk_rating": "High",
            "attack_vectors": [
                "Unnecessary features enabled (ports, services, accounts)",
                "Default accounts and passwords unchanged",
                "Error handling revealing stack traces",
                "Upgraded systems with outdated security settings",
                "Security settings in frameworks not set to secure values"
            ],
            "mitigations": [
                "Implement repeatable hardening process",
                "Use minimal platform without unnecessary features",
                "Review and update configurations for security patches/notes",
                "Implement segmented application architecture",
                "Send security directives to clients (Security Headers)"
            ],
            "keywords": ["configuration", "hardening", "default", "debug", "error handling", "headers"]
        },
        "A06:2021": {
            "id": "A06:2021",
            "title": "Vulnerable and Outdated Components",
            "description": "Using components with known vulnerabilities",
            "risk_rating": "High",
            "attack_vectors": [
                "Using libraries with known CVEs",
                "Unsupported or out-of-date software",
                "Not scanning for vulnerabilities regularly",
                "Not testing compatibility of updated libraries"
            ],
            "mitigations": [
                "Remove unused dependencies and features",
                "Continuously inventory component versions (SBOM)",
                "Monitor sources like CVE, NVD for vulnerabilities",
                "Only obtain components from official sources",
                "Monitor for unmaintained libraries"
            ],
            "keywords": ["dependencies", "library", "cve", "vulnerable", "outdated", "sbom", "sca"]
        },
        "A07:2021": {
            "id": "A07:2021",
            "title": "Identification and Authentication Failures",
            "description": "Confirmation of user's identity, authentication, and session management weaknesses",
            "risk_rating": "High",
            "attack_vectors": [
                "Credential stuffing (automated attack with known credentials)",
                "Brute force attacks",
                "Weak or default passwords allowed",
                "Missing or ineffective MFA",
                "Session identifiers exposed in URL",
                "Session tokens not properly invalidated"
            ],
            "mitigations": [
                "Implement multi-factor authentication",
                "Do not ship/deploy with default credentials",
                "Implement weak password checks",
                "Harden account recovery/registration paths",
                "Limit failed login attempts with progressive delays",
                "Use server-side secure session manager"
            ],
            "keywords": ["authentication", "identity", "session", "mfa", "password", "credential", "login"]
        },
        "A08:2021": {
            "id": "A08:2021",
            "title": "Software and Data Integrity Failures",
            "description": "Code and infrastructure that does not protect against integrity violations",
            "risk_rating": "High",
            "attack_vectors": [
                "Malicious updates to libraries",
                "Insecure CI/CD pipeline",
                "Auto-update functionality without verification",
                "Unsafe deserialization of untrusted data"
            ],
            "mitigations": [
                "Use digital signatures to verify software/data",
                "Use trusted repositories for libraries and dependencies",
                "Use software supply chain security tool (OWASP Dependency-Check)",
                "Ensure CI/CD pipeline has proper segregation and access control",
                "Avoid sending unsigned/unencrypted serialized data to untrusted clients"
            ],
            "keywords": ["integrity", "supply chain", "ci/cd", "deserialization", "update", "signature"]
        },
        "A09:2021": {
            "id": "A09:2021",
            "title": "Security Logging and Monitoring Failures",
            "description": "Without logging and monitoring, breaches cannot be detected",
            "risk_rating": "Medium",
            "attack_vectors": [
                "Auditable events not logged",
                "Warnings and errors generate no log messages",
                "Logs only stored locally",
                "Alerting thresholds not in place",
                "Penetration testing doesn't trigger alerts"
            ],
            "mitigations": [
                "Log all login, access control, and server-side input validation failures",
                "Ensure logs are in format that can be consumed by log management solutions",
                "Ensure high-value transactions have audit trail with integrity controls",
                "Establish effective monitoring and alerting",
                "Establish incident response and recovery plan"
            ],
            "keywords": ["logging", "monitoring", "audit", "siem", "alerting", "incident response"]
        },
        "A10:2021": {
            "id": "A10:2021",
            "title": "Server-Side Request Forgery (SSRF)",
            "description": "Web application fetches remote resource without validating user-supplied URL",
            "risk_rating": "High",
            "attack_vectors": [
                "Accessing internal services behind firewalls",
                "Scanning internal ports",
                "Reading local files via file:// scheme",
                "Accessing cloud service metadata APIs"
            ],
            "mitigations": [
                "Segment remote resource access functionality",
                "Enforce URL schemas, ports, and destinations with allowlist",
                "Disable HTTP redirections",
                "Do not send raw responses to clients",
                "Sanitize and validate all client-supplied input data"
            ],
            "keywords": ["ssrf", "url", "fetch", "request", "internal", "metadata"]
        }
    }
    
    # ===========================================
    # OWASP API Security Top 10 (2023)
    # ===========================================
    OWASP_API_TOP_10 = {
        "API1:2023": {
            "id": "API1:2023",
            "title": "Broken Object Level Authorization",
            "description": "APIs exposing endpoints handling object identifiers without proper authorization",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Manipulating object IDs in API requests",
                "Accessing resources belonging to other users",
                "BOLA through batch operations"
            ],
            "mitigations": [
                "Implement proper authorization checks at object level",
                "Use unpredictable object identifiers (UUIDs)",
                "Write tests to evaluate authorization vulnerabilities"
            ],
            "keywords": ["bola", "object", "authorization", "idor", "api"]
        },
        "API2:2023": {
            "id": "API2:2023",
            "title": "Broken Authentication",
            "description": "Flawed authentication mechanisms in APIs",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Weak password requirements",
                "Missing brute force protection",
                "Credential stuffing",
                "JWT vulnerabilities"
            ],
            "mitigations": [
                "Implement strong authentication mechanisms",
                "Use rate limiting and lockout policies",
                "Implement MFA for sensitive operations"
            ],
            "keywords": ["authentication", "jwt", "token", "api key", "oauth"]
        },
        "API3:2023": {
            "id": "API3:2023",
            "title": "Broken Object Property Level Authorization",
            "description": "Lack of or improper authorization at property level within objects",
            "risk_rating": "High",
            "attack_vectors": [
                "Mass assignment vulnerabilities",
                "Excessive data exposure in responses",
                "Modifying object properties that should be read-only"
            ],
            "mitigations": [
                "Validate and filter properties based on user permissions",
                "Avoid generic binding methods",
                "Define explicit schemas for data exchange"
            ],
            "keywords": ["mass assignment", "property", "field", "excessive data"]
        },
        "API4:2023": {
            "id": "API4:2023",
            "title": "Unrestricted Resource Consumption",
            "description": "API not restricting size or number of resources requested",
            "risk_rating": "High",
            "attack_vectors": [
                "DoS through resource exhaustion",
                "API parameter tampering for large responses",
                "Batch operation abuse"
            ],
            "mitigations": [
                "Implement rate limiting per client/API key",
                "Add pagination with reasonable defaults",
                "Validate and limit request parameters"
            ],
            "keywords": ["rate limit", "dos", "resource", "pagination", "throttling"]
        },
        "API5:2023": {
            "id": "API5:2023",
            "title": "Broken Function Level Authorization",
            "description": "Complex access control policies with unclear separation between normal and admin functions",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Accessing admin endpoints as regular user",
                "Changing HTTP methods to bypass controls",
                "Manipulating parameters to elevate privileges"
            ],
            "mitigations": [
                "Default deny for all endpoints",
                "Ensure administrative functions are properly protected",
                "Implement consistent authorization checks"
            ],
            "keywords": ["function", "admin", "endpoint", "privilege escalation"]
        },
        "API6:2023": {
            "id": "API6:2023",
            "title": "Unrestricted Access to Sensitive Business Flows",
            "description": "Exposing business flows without compensating controls",
            "risk_rating": "High",
            "attack_vectors": [
                "Automated purchasing bypassing human verification",
                "Ticket scalping through API automation",
                "Comment spam and fake reviews"
            ],
            "mitigations": [
                "Identify critical business flows",
                "Implement device fingerprinting",
                "Use CAPTCHA or bot detection",
                "Block IP ranges of known malicious sources"
            ],
            "keywords": ["business logic", "automation", "bot", "abuse", "flow"]
        },
        "API7:2023": {
            "id": "API7:2023",
            "title": "Server Side Request Forgery",
            "description": "API fetches remote resources based on user input without validation",
            "risk_rating": "High",
            "attack_vectors": [
                "Internal port scanning via API",
                "Accessing cloud metadata services",
                "Reading internal files"
            ],
            "mitigations": [
                "Validate and sanitize all user-supplied URLs",
                "Use allowlists for external services",
                "Disable unnecessary URL schemes"
            ],
            "keywords": ["ssrf", "url", "fetch", "webhook", "callback"]
        },
        "API8:2023": {
            "id": "API8:2023",
            "title": "Security Misconfiguration",
            "description": "Improper or insecure API configuration",
            "risk_rating": "High",
            "attack_vectors": [
                "Missing security headers",
                "Exposed debug endpoints",
                "Verbose error messages",
                "CORS misconfiguration"
            ],
            "mitigations": [
                "Implement hardening procedures",
                "Review configurations regularly",
                "Automate configuration assessment"
            ],
            "keywords": ["configuration", "cors", "headers", "debug", "error"]
        },
        "API9:2023": {
            "id": "API9:2023",
            "title": "Improper Inventory Management",
            "description": "Lack of proper API inventory and version management",
            "risk_rating": "Medium",
            "attack_vectors": [
                "Exploiting old API versions",
                "Accessing deprecated endpoints",
                "Shadow APIs"
            ],
            "mitigations": [
                "Maintain API inventory/documentation",
                "Implement API versioning strategy",
                "Retire old API versions properly"
            ],
            "keywords": ["inventory", "version", "documentation", "deprecated", "shadow api"]
        },
        "API10:2023": {
            "id": "API10:2023",
            "title": "Unsafe Consumption of APIs",
            "description": "Exposing vulnerabilities when consuming third-party APIs",
            "risk_rating": "High",
            "attack_vectors": [
                "Trusting third-party API responses without validation",
                "Following redirects blindly",
                "Not implementing timeouts"
            ],
            "mitigations": [
                "Validate all third-party API responses",
                "Use TLS for all communications",
                "Implement proper error handling and timeouts"
            ],
            "keywords": ["third-party", "external api", "integration", "webhook"]
        }
    }
    
    # ===========================================
    # OWASP LLM AI Top 10 (2025)
    # ===========================================
    OWASP_LLM_TOP_10 = {
        "LLM01:2025": {
            "id": "LLM01:2025",
            "title": "Prompt Injection",
            "description": "Manipulating LLM through crafted inputs to cause unintended actions",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Direct prompt injection through user input",
                "Indirect prompt injection through external content",
                "Jailbreaking to bypass content filters",
                "Prompt leaking to extract system prompts"
            ],
            "mitigations": [
                "Constrain model behavior with strict system prompts",
                "Validate and sanitize all inputs",
                "Implement input/output filtering",
                "Use privilege separation between LLM and external systems",
                "Human-in-the-loop for critical actions",
                "Mark and distinguish untrusted content"
            ],
            "keywords": ["prompt injection", "llm", "jailbreak", "prompt leak", "ai", "chatbot", "gpt"]
        },
        "LLM02:2025": {
            "id": "LLM02:2025",
            "title": "Sensitive Information Disclosure",
            "description": "LLM revealing confidential data through responses",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Training data extraction",
                "PII leakage in responses",
                "Model inversion attacks",
                "Membership inference attacks"
            ],
            "mitigations": [
                "Apply data sanitization and scrubbing on training data",
                "Implement strict output filtering for sensitive data",
                "Use differential privacy techniques",
                "Limit model's access to sensitive data",
                "Implement access controls on data returned"
            ],
            "keywords": ["data leakage", "pii", "training data", "model inversion", "privacy", "llm"]
        },
        "LLM03:2025": {
            "id": "LLM03:2025",
            "title": "Supply Chain Vulnerabilities",
            "description": "Compromises in the LLM supply chain affecting model integrity",
            "risk_rating": "High",
            "attack_vectors": [
                "Poisoned pre-trained models",
                "Compromised training datasets",
                "Malicious plugins/extensions",
                "Vulnerable dependencies in ML frameworks"
            ],
            "mitigations": [
                "Vet third-party models and data sources",
                "Use model provenance tracking",
                "Perform security audits of plugins",
                "Maintain SBOM for ML components",
                "Use trusted model registries"
            ],
            "keywords": ["supply chain", "model", "dataset", "plugin", "dependency", "ml framework"]
        },
        "LLM04:2025": {
            "id": "LLM04:2025",
            "title": "Data and Model Poisoning",
            "description": "Tampering with training data or model to introduce vulnerabilities",
            "risk_rating": "High",
            "attack_vectors": [
                "Training data poisoning",
                "Model weight manipulation",
                "Backdoor injection during training",
                "Federated learning attacks"
            ],
            "mitigations": [
                "Validate training data integrity",
                "Implement data provenance tracking",
                "Use anomaly detection for training",
                "Apply robust training techniques",
                "Regular model auditing"
            ],
            "keywords": ["poisoning", "training", "backdoor", "adversarial", "federated learning"]
        },
        "LLM05:2025": {
            "id": "LLM05:2025",
            "title": "Improper Output Handling",
            "description": "Failing to validate, sanitize, or handle LLM outputs safely",
            "risk_rating": "High",
            "attack_vectors": [
                "XSS through LLM-generated content",
                "Code injection via code generation",
                "Command injection through tool calls",
                "SSRF via LLM-generated URLs"
            ],
            "mitigations": [
                "Treat LLM output as untrusted",
                "Apply context-appropriate encoding/escaping",
                "Validate outputs before passing to other systems",
                "Implement sandboxing for code execution",
                "Use allowlists for permitted actions"
            ],
            "keywords": ["output", "sanitization", "code generation", "tool use", "xss", "injection"]
        },
        "LLM06:2025": {
            "id": "LLM06:2025",
            "title": "Excessive Agency",
            "description": "Granting LLM too much autonomy leading to unintended consequences",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Autonomous actions without approval",
                "Excessive permissions to external systems",
                "Uncontrolled tool/function calling",
                "Agentic loops executing harmful sequences"
            ],
            "mitigations": [
                "Limit LLM's permissions and capabilities",
                "Implement human-in-the-loop for critical actions",
                "Use least privilege principle for tool access",
                "Rate limit autonomous actions",
                "Log and monitor all LLM actions",
                "Implement action confirmation workflows"
            ],
            "keywords": ["agency", "autonomous", "agent", "agentic", "tool calling", "function calling", "permissions"]
        },
        "LLM07:2025": {
            "id": "LLM07:2025",
            "title": "System Prompt Leakage",
            "description": "Extraction or disclosure of system prompts and configuration",
            "risk_rating": "Medium",
            "attack_vectors": [
                "Prompt extraction attacks",
                "Side-channel inference of prompts",
                "Social engineering through prompt manipulation"
            ],
            "mitigations": [
                "Assume system prompts can be discovered",
                "Don't include secrets in system prompts",
                "Implement prompt protection mechanisms",
                "Monitor for prompt extraction attempts"
            ],
            "keywords": ["system prompt", "prompt extraction", "configuration", "secrets"]
        },
        "LLM08:2025": {
            "id": "LLM08:2025",
            "title": "Vector and Embedding Weaknesses",
            "description": "Vulnerabilities in vector databases and embedding systems used with LLMs",
            "risk_rating": "Medium",
            "attack_vectors": [
                "Adversarial embeddings",
                "Embedding collision attacks",
                "Retrieval augmented generation (RAG) poisoning",
                "Vector database injection"
            ],
            "mitigations": [
                "Validate embedded content before use",
                "Implement access controls on vector databases",
                "Use separate embedding spaces for different trust levels",
                "Monitor for anomalous embeddings",
                "Apply content filtering on retrieved documents"
            ],
            "keywords": ["vector", "embedding", "rag", "retrieval", "similarity search"]
        },
        "LLM09:2025": {
            "id": "LLM09:2025",
            "title": "Misinformation",
            "description": "LLM generating false or misleading information (hallucinations)",
            "risk_rating": "High",
            "attack_vectors": [
                "Hallucination exploitation",
                "Confidence manipulation",
                "Fact distortion through context manipulation",
                "Citation fabrication"
            ],
            "mitigations": [
                "Implement retrieval-augmented generation (RAG)",
                "Apply fact-checking and verification layers",
                "Use confidence scoring and uncertainty quantification",
                "Require citations and source verification",
                "Implement human review for critical outputs"
            ],
            "keywords": ["hallucination", "misinformation", "fact-checking", "accuracy", "citation"]
        },
        "LLM10:2025": {
            "id": "LLM10:2025",
            "title": "Unbounded Consumption",
            "description": "Denial of service through excessive resource consumption",
            "risk_rating": "High",
            "attack_vectors": [
                "Prompt complexity attacks",
                "Repetitive query flooding",
                "Variable-length input exploitation",
                "Resource exhaustion through context expansion"
            ],
            "mitigations": [
                "Implement input length and complexity limits",
                "Use rate limiting and quotas",
                "Set maximum token limits",
                "Implement cost monitoring and alerts",
                "Use request queuing with timeouts"
            ],
            "keywords": ["dos", "resource", "token", "rate limit", "cost", "consumption"]
        }
    }
    
    # ===========================================
    # AI/Agentic-specific threat patterns
    # ===========================================
    AGENTIC_AI_THREATS = {
        "AGENT01": {
            "id": "AGENT01",
            "title": "Uncontrolled Agent Autonomy",
            "description": "AI agents executing actions without proper human oversight or approval",
            "risk_rating": "Critical",
            "attack_vectors": [
                "Agents making irreversible changes without confirmation",
                "Chain reactions through inter-agent communication",
                "Unintended goal pursuit through reward hacking"
            ],
            "mitigations": [
                "Implement approval workflows for critical actions",
                "Set action boundaries and rate limits",
                "Use human-in-the-loop for high-impact decisions",
                "Implement kill switches and emergency stops",
                "Log all agent actions for audit"
            ],
            "keywords": ["agent", "autonomy", "autonomous", "agentic", "ai agent"]
        },
        "AGENT02": {
            "id": "AGENT02",
            "title": "Tool/API Abuse by Agents",
            "description": "AI agents misusing tools, APIs, or external services",
            "risk_rating": "High",
            "attack_vectors": [
                "Agents calling APIs with excessive permissions",
                "Data exfiltration through tool misuse",
                "Privilege escalation via tool chaining"
            ],
            "mitigations": [
                "Apply least privilege to agent tool access",
                "Implement tool-specific rate limits",
                "Validate all tool inputs and outputs",
                "Sandbox tool execution environments",
                "Monitor for anomalous tool usage patterns"
            ],
            "keywords": ["tool", "api", "function calling", "mcp", "tool use"]
        },
        "AGENT03": {
            "id": "AGENT03",
            "title": "Agent Memory Manipulation",
            "description": "Attacks targeting agent memory, context, or state",
            "risk_rating": "High",
            "attack_vectors": [
                "Poisoning agent context through injected content",
                "Memory overflow leading to context loss",
                "Persistent memory manipulation across sessions"
            ],
            "mitigations": [
                "Implement memory validation and sanitization",
                "Use separate memory stores for different trust levels",
                "Apply encryption to sensitive memory contents",
                "Implement memory size limits and pruning",
                "Regular memory integrity checks"
            ],
            "keywords": ["memory", "context", "state", "persistence", "conversation history"]
        },
        "AGENT04": {
            "id": "AGENT04",
            "title": "Multi-Agent Coordination Attacks",
            "description": "Exploiting communication between multiple AI agents",
            "risk_rating": "High",
            "attack_vectors": [
                "Prompt injection through inter-agent messages",
                "Cascading failures through agent dependencies",
                "Consensus manipulation in multi-agent systems"
            ],
            "mitigations": [
                "Authenticate and validate inter-agent communications",
                "Implement message signing between agents",
                "Use isolated execution environments per agent",
                "Monitor for abnormal communication patterns",
                "Implement circuit breakers for agent failures"
            ],
            "keywords": ["multi-agent", "swarm", "coordination", "communication", "orchestration"]
        },
        "AGENT05": {
            "id": "AGENT05",
            "title": "Goal Misalignment and Specification Gaming",
            "description": "Agents finding unintended ways to achieve specified goals",
            "risk_rating": "High",
            "attack_vectors": [
                "Reward hacking through loophole exploitation",
                "Side effects from goal optimization",
                "Deceptive behavior to appear aligned"
            ],
            "mitigations": [
                "Define comprehensive goal specifications",
                "Implement multiple aligned evaluation metrics",
                "Use adversarial testing for goal alignment",
                "Monitor for unexpected optimization behaviors",
                "Implement interpretability tools"
            ],
            "keywords": ["alignment", "goal", "reward", "optimization", "behavior"]
        }
    }
    
    # STRIDE to OWASP mapping
    STRIDE_TO_OWASP = {
        "Spoofing": ["A07:2021", "API2:2023", "LLM01:2025"],
        "Tampering": ["A03:2021", "A08:2021", "API3:2023", "LLM04:2025"],
        "Repudiation": ["A09:2021", "API9:2023", "LLM06:2025"],
        "Information Disclosure": ["A01:2021", "A02:2021", "API1:2023", "LLM02:2025"],
        "Denial of Service": ["API4:2023", "LLM10:2025"],
        "Elevation of Privilege": ["A01:2021", "API5:2023", "LLM06:2025"]
    }
    
    def __init__(self):
        # Combine all OWASP threats for lookup
        self.all_threats = {
            **self.OWASP_TOP_10_WEB,
            **self.OWASP_API_TOP_10,
            **self.OWASP_LLM_TOP_10,
            **self.AGENTIC_AI_THREATS
        }
    
    def identify_owasp_threats(
        self,
        system_description: str,
        components: List[str],
        data_types: List[str],
        has_ai: bool = False,
        has_api: bool = False,
        has_agents: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Identify applicable OWASP threats based on system characteristics.
        
        Args:
            system_description: Description of the system
            components: List of system components
            data_types: Types of data processed
            has_ai: Whether system includes AI/ML components
            has_api: Whether system exposes APIs
            has_agents: Whether system uses AI agents
        
        Returns:
            List of applicable OWASP threats with details
        """
        applicable_threats = []
        text_to_search = f"{system_description} {' '.join(components)} {' '.join(data_types)}".lower()
        
        # Always include relevant web application threats
        for threat_id, threat in self.OWASP_TOP_10_WEB.items():
            if any(kw in text_to_search for kw in threat["keywords"]):
                applicable_threats.append({
                    **threat,
                    "framework": "OWASP Top 10 Web",
                    "applicability": "high"
                })
        
        # Include API threats if API is involved
        if has_api or "api" in text_to_search or "rest" in text_to_search:
            for threat_id, threat in self.OWASP_API_TOP_10.items():
                if any(kw in text_to_search for kw in threat["keywords"]):
                    applicable_threats.append({
                        **threat,
                        "framework": "OWASP API Security Top 10",
                        "applicability": "high"
                    })
        
        # Include LLM/AI threats if AI is involved
        if has_ai or any(kw in text_to_search for kw in ["llm", "ai", "ml", "model", "gpt", "chatbot", "neural"]):
            for threat_id, threat in self.OWASP_LLM_TOP_10.items():
                applicable_threats.append({
                    **threat,
                    "framework": "OWASP LLM AI Top 10",
                    "applicability": "high" if any(kw in text_to_search for kw in threat["keywords"]) else "medium"
                })
        
        # Include agentic threats if agents are involved
        if has_agents or any(kw in text_to_search for kw in ["agent", "agentic", "autonomous", "tool calling", "function calling"]):
            for threat_id, threat in self.AGENTIC_AI_THREATS.items():
                applicable_threats.append({
                    **threat,
                    "framework": "Agentic AI Security",
                    "applicability": "high" if any(kw in text_to_search for kw in threat["keywords"]) else "medium"
                })
        
        return applicable_threats
    
    def map_stride_to_owasp(self, stride_category: str) -> List[str]:
        """Map a STRIDE category to relevant OWASP threat IDs"""
        return self.STRIDE_TO_OWASP.get(stride_category, [])
    
    def get_threat_details(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific OWASP threat"""
        return self.all_threats.get(threat_id)
    
    def get_ai_specific_mitigations(self, has_llm: bool = True, has_agents: bool = False) -> List[Dict[str, Any]]:
        """
        Get AI-specific security mitigations.
        
        Args:
            has_llm: Whether system uses LLMs
            has_agents: Whether system uses AI agents
        
        Returns:
            List of recommended mitigations
        """
        mitigations = []
        
        if has_llm:
            mitigations.extend([
                {
                    "id": "AI-MIT-01",
                    "title": "Input/Output Filtering",
                    "description": "Implement comprehensive input and output filtering for LLM interactions",
                    "implementation": [
                        "Filter and validate all user inputs before sending to LLM",
                        "Scan LLM outputs for sensitive data (PII, credentials)",
                        "Implement content classifiers for harmful outputs",
                        "Use guardrails for topic and behavior constraints"
                    ],
                    "priority": "critical",
                    "owasp_refs": ["LLM01:2025", "LLM02:2025", "LLM05:2025"]
                },
                {
                    "id": "AI-MIT-02",
                    "title": "Prompt Security",
                    "description": "Secure system prompts and prevent prompt injection attacks",
                    "implementation": [
                        "Clearly separate system instructions from user input",
                        "Mark untrusted content with special delimiters",
                        "Avoid including secrets in system prompts",
                        "Implement prompt hardening techniques"
                    ],
                    "priority": "critical",
                    "owasp_refs": ["LLM01:2025", "LLM07:2025"]
                },
                {
                    "id": "AI-MIT-03",
                    "title": "Output Verification",
                    "description": "Verify and validate all LLM-generated outputs",
                    "implementation": [
                        "Implement fact-checking for critical outputs",
                        "Use RAG with trusted knowledge bases",
                        "Add confidence scoring to responses",
                        "Require human review for high-impact actions"
                    ],
                    "priority": "high",
                    "owasp_refs": ["LLM09:2025", "LLM05:2025"]
                }
            ])
        
        if has_agents:
            mitigations.extend([
                {
                    "id": "AI-MIT-04",
                    "title": "Agent Action Controls",
                    "description": "Implement strict controls over agent actions and capabilities",
                    "implementation": [
                        "Define explicit action boundaries for each agent",
                        "Implement approval workflows for destructive actions",
                        "Use least privilege for tool/API access",
                        "Log all agent actions with full context"
                    ],
                    "priority": "critical",
                    "owasp_refs": ["LLM06:2025", "AGENT01", "AGENT02"]
                },
                {
                    "id": "AI-MIT-05",
                    "title": "Human-in-the-Loop",
                    "description": "Ensure human oversight for critical agent operations",
                    "implementation": [
                        "Require human approval for high-impact actions",
                        "Implement confirmation dialogs for destructive operations",
                        "Set up alerting for anomalous agent behavior",
                        "Create kill switches for emergency stops"
                    ],
                    "priority": "critical",
                    "owasp_refs": ["AGENT01", "LLM06:2025"]
                },
                {
                    "id": "AI-MIT-06",
                    "title": "Agent Memory Security",
                    "description": "Protect agent memory and context from manipulation",
                    "implementation": [
                        "Sanitize content before adding to agent memory",
                        "Implement memory size limits and pruning",
                        "Use encryption for sensitive memory contents",
                        "Validate memory integrity periodically"
                    ],
                    "priority": "high",
                    "owasp_refs": ["AGENT03", "LLM08:2025"]
                }
            ])
        
        return mitigations
    
    def generate_compliance_report(
        self,
        identified_threats: List[str],
        has_ai: bool = False,
        has_agents: bool = False
    ) -> Dict[str, Any]:
        """
        Generate OWASP compliance report for identified threats.
        
        Args:
            identified_threats: List of identified OWASP threat IDs
            has_ai: Whether AI components are present
            has_agents: Whether AI agents are present
        
        Returns:
            Compliance report with gaps and recommendations
        """
        # Determine required frameworks
        frameworks = ["OWASP Top 10 Web"]
        if has_ai:
            frameworks.append("OWASP LLM AI Top 10")
        if has_agents:
            frameworks.append("Agentic AI Security")
        
        # Get all threats from required frameworks
        required_threats = []
        if "OWASP Top 10 Web" in frameworks:
            required_threats.extend(self.OWASP_TOP_10_WEB.keys())
        if "OWASP LLM AI Top 10" in frameworks:
            required_threats.extend(self.OWASP_LLM_TOP_10.keys())
        if "Agentic AI Security" in frameworks:
            required_threats.extend(self.AGENTIC_AI_THREATS.keys())
        
        # Calculate coverage
        covered = set(identified_threats) & set(required_threats)
        missing = set(required_threats) - set(identified_threats)
        
        # Get mitigations for AI if applicable
        ai_mitigations = self.get_ai_specific_mitigations(has_ai, has_agents)
        
        return {
            "frameworks_assessed": frameworks,
            "total_threats_assessed": len(required_threats),
            "threats_identified": len(covered),
            "coverage_percentage": round(len(covered) / len(required_threats) * 100, 1) if required_threats else 100,
            "covered_threats": list(covered),
            "missing_assessments": list(missing),
            "critical_gaps": [t for t in missing if self.all_threats.get(t, {}).get("risk_rating") == "Critical"],
            "ai_specific_mitigations": ai_mitigations if has_ai or has_agents else [],
            "recommendations": self._generate_recommendations(missing, has_ai, has_agents)
        }
    
    def _generate_recommendations(
        self,
        missing: Set[str],
        has_ai: bool,
        has_agents: bool
    ) -> List[str]:
        """Generate prioritized recommendations based on gaps"""
        recommendations = []
        
        # Prioritize critical gaps
        for threat_id in missing:
            threat = self.all_threats.get(threat_id, {})
            if threat.get("risk_rating") == "Critical":
                recommendations.append(
                    f"CRITICAL: Assess and mitigate {threat_id} - {threat.get('title', 'Unknown')}"
                )
        
        # Add AI-specific recommendations
        if has_ai and "LLM01:2025" in missing:
            recommendations.insert(0, "URGENT: Implement prompt injection protection - this is the #1 LLM security risk")
        
        if has_agents and "AGENT01" in missing:
            recommendations.insert(0, "URGENT: Implement agent action controls and human-in-the-loop for autonomous agents")
        
        return recommendations[:10]  # Return top 10 recommendations
