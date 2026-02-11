"""
Enhanced Threat Models
Pydantic v2 models for reader-proof threat documentation
"""

from typing import Dict, Any, List, Optional, Literal
from datetime import datetime
from enum import Enum
import uuid
import re

from pydantic import BaseModel, Field, field_validator, model_validator


# ===========================================
# Enums
# ===========================================

class MitigationType(str, Enum):
    """Mitigation control type classification"""
    PREVENT = "prevent"
    DETECT = "detect"
    RESPOND = "respond"


class MitigationStatus(str, Enum):
    """Mitigation implementation status"""
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"


class ConfidenceLevel(str, Enum):
    """Confidence level for threat assessment"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ===========================================
# Keyword Patterns for Mitigation Type Inference
# ===========================================

PREVENT_KEYWORDS = [
    "waf", "cloudflare", "shield", "rate limit", "rate-limit", "ratelimit",
    "timeout", "mtls", "mTLS", "mutual tls", "csp", "content security policy",
    "validation", "validate", "sanitize", "sanitization", "escape", "escaping",
    "least privilege", "principle of least", "ingress", "egress", "nginx",
    "uvicorn", "autoscal", "encrypt", "encryption", "aes", "rsa", "tls",
    "ssl", "https", "parameterized", "prepared statement", "whitelist",
    "allowlist", "deny", "block", "firewall", "cors", "csrf", "xss prevention",
    "input filter", "output encod", "secure header", "hsts", "x-frame",
    "x-content-type", "referrer-policy", "permission", "rbac", "abac",
    "authentication", "authorization", "mfa", "2fa", "totp", "jwt validation",
    "token validation", "signature verif", "hash", "bcrypt", "argon2",
    "scrypt", "pbkdf2", "key rotation", "secret rotation", "vault",
    "secrets manager", "kms", "hsm", "certificate", "pin", "integrity check"
]

DETECT_KEYWORDS = [
    "alert", "alerting", "monitor", "monitoring", "log", "logging", "logger",
    "dashboard", "siem", "anomaly", "anomalies", "audit", "auditing",
    "observe", "observability", "track", "tracking", "metric", "metrics",
    "telemetry", "trace", "tracing", "span", "opentelemetry", "datadog",
    "splunk", "elk", "elasticsearch", "kibana", "grafana", "prometheus",
    "cloudwatch", "stackdriver", "newrelic", "dynatrace", "apm", "rum",
    "intrusion detection", "ids", "ips", "waf log", "access log",
    "security log", "event log", "correlation", "baseline", "threshold",
    "notify", "notification", "pagerduty", "opsgenie", "slack alert",
    "email alert", "webhook", "scan", "scanning", "vulnerability scan",
    "penetration test", "pentest", "code review", "sast", "dast", "iast"
]

RESPOND_KEYWORDS = [
    "runbook", "playbook", "rollback", "restore", "recovery", "backup",
    "block", "blocking", "challenge", "captcha", "degrade", "degradation",
    "failover", "failback", "circuit breaker", "bulkhead", "retry",
    "incident", "incident response", "ir plan", "quarantine", "isolate",
    "isolation", "contain", "containment", "eradicate", "eradication",
    "remediate", "remediation", "patch", "patching", "hotfix", "mitigate",
    "workaround", "compensating control", "manual review", "human in loop",
    "escalate", "escalation", "on-call", "oncall", "disaster recovery",
    "dr plan", "business continuity", "bcp", "rto", "rpo", "sla",
    "postmortem", "post-mortem", "root cause", "rca", "lessons learned",
    "war room", "bridge call", "status page", "communication plan"
]


def infer_mitigation_type(text: str) -> MitigationType:
    """
    Infer mitigation type from text using keyword matching.
    
    Priority: PREVENT > DETECT > RESPOND (most specific first)
    """
    text_lower = text.lower()
    
    # Check for PREVENT keywords
    for keyword in PREVENT_KEYWORDS:
        if keyword in text_lower:
            return MitigationType.PREVENT
    
    # Check for DETECT keywords
    for keyword in DETECT_KEYWORDS:
        if keyword in text_lower:
            return MitigationType.DETECT
    
    # Check for RESPOND keywords
    for keyword in RESPOND_KEYWORDS:
        if keyword in text_lower:
            return MitigationType.RESPOND
    
    # Default to PREVENT (most common for security mitigations)
    return MitigationType.PREVENT


# ===========================================
# Structured Mitigation Model
# ===========================================

class StructuredMitigation(BaseModel):
    """A structured mitigation with type, status, owner, and verification"""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    text: str = Field(..., min_length=1, description="Mitigation description")
    mitigation_type: MitigationType = Field(
        default=MitigationType.PREVENT,
        description="Control type: prevent, detect, or respond"
    )
    status: MitigationStatus = Field(
        default=MitigationStatus.PLANNED,
        description="Implementation status"
    )
    owner: Optional[str] = Field(
        default=None,
        description="Person/team responsible"
    )
    verification: List[str] = Field(
        default_factory=list,
        description="Verification checks, tests, alerts, or runbooks"
    )
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    
    model_config = {"extra": "allow"}
    
    @classmethod
    def from_legacy_string(cls, text: str) -> "StructuredMitigation":
        """Create a StructuredMitigation from a legacy string"""
        return cls(
            text=text,
            mitigation_type=infer_mitigation_type(text),
            status=MitigationStatus.PLANNED,
        )


# ===========================================
# Attack Scenario Model
# ===========================================

class AttackScenario(BaseModel):
    """Describes the attack scenario for a threat"""
    
    preconditions: List[str] = Field(
        default_factory=list,
        description="Conditions that must be true for the attack"
    )
    steps: List[str] = Field(
        default_factory=list,
        description="Attack steps (3-8 recommended)"
    )
    impact_narrative: str = Field(
        default="",
        description="1-2 sentence impact description"
    )
    
    model_config = {"extra": "allow"}


# ===========================================
# Flow Map Models
# ===========================================

class FlowMapComponent(BaseModel):
    """A component in the flow map"""
    
    id: str
    name: str
    type: str = Field(
        description="Component type: process, data_store, external_entity"
    )
    trust_boundary: Optional[str] = Field(
        default=None,
        description="Trust boundary this component belongs to"
    )
    description: Optional[str] = None
    layer: Optional[str] = Field(
        default=None,
        description="Architecture layer: frontend, backend, data, external"
    )
    
    model_config = {"extra": "allow"}


class FlowMapFlow(BaseModel):
    """A data flow between components"""
    
    id: str
    name: str = Field(default="", description="Flow label/name")
    source_id: str = Field(alias="source", description="Source component ID")
    target_id: str = Field(alias="target", description="Target component ID")
    protocol: Optional[str] = Field(default=None, description="Protocol used")
    auth: Optional[str] = Field(default=None, description="Authentication method")
    data_classification: Optional[str] = Field(
        default=None,
        description="Data classification: public, internal, confidential, restricted"
    )
    crosses_trust_boundary: bool = Field(
        default=False,
        description="Whether this flow crosses a trust boundary"
    )
    encrypted: bool = Field(default=False, description="Whether flow is encrypted")
    
    model_config = {"extra": "allow", "populate_by_name": True}


class FlowMapData(BaseModel):
    """Complete flow map data"""
    
    components: List[FlowMapComponent] = Field(default_factory=list)
    flows: List[FlowMapFlow] = Field(default_factory=list)
    trust_boundaries: List[Dict[str, Any]] = Field(default_factory=list)
    
    model_config = {"extra": "allow"}


# ===========================================
# Enhanced Threat Model
# ===========================================

class ThreatEnhanced(BaseModel):
    """
    Enhanced threat model with location mapping, attack scenarios,
    structured mitigations, and transparent risk scoring.
    """
    
    # Core fields (backward compatible)
    id: str
    title: str
    description: str
    category: str = "Information Disclosure"
    severity: str = "medium"
    affected_component: str = ""  # Legacy single component
    attack_vector: str = ""
    mitigations: List[str] = Field(default_factory=list)  # Legacy string list
    dread_score: Dict[str, float] = Field(
        default_factory=lambda: {
            "damage": 5, "reproducibility": 5, "exploitability": 5,
            "affected_users": 5, "discoverability": 5
        }
    )
    overall_risk: float = 5.0
    
    # Existing optional fields
    stride_category: Optional[str] = None
    status: str = "identified"  # identified, mitigated, accepted, transferred
    zone: Optional[str] = None
    trust_boundary: Optional[str] = None
    compliance_mappings: Dict[str, Any] = Field(default_factory=dict)
    owasp_mappings: Optional[Dict[str, List[str]]] = None
    methodology: Optional[str] = None  # stride, pasta, maestro
    
    # NEW: Location/Mapping fields
    affected_component_ids: List[str] = Field(
        default_factory=list,
        description="IDs of affected components in the flow map"
    )
    impacted_flow_ids: List[str] = Field(
        default_factory=list,
        description="IDs of impacted data flows"
    )
    trust_boundaries: List[str] = Field(
        default_factory=list,
        description="Trust boundaries this threat affects"
    )
    assets_impacted: List[str] = Field(
        default_factory=list,
        description="Assets at risk: PII, tokens, secrets, admin config, etc."
    )
    
    # NEW: Attack Scenario
    preconditions: List[str] = Field(
        default_factory=list,
        description="Conditions required for the attack"
    )
    attack_scenario_steps: List[str] = Field(
        default_factory=list,
        description="Step-by-step attack scenario (3-8 steps)"
    )
    impact_narrative: str = Field(
        default="",
        description="1-2 sentence impact description"
    )
    
    # NEW: Risk Transparency
    scoring_model: str = Field(
        default="DREAD_AVG_V1",
        description="Scoring model used"
    )
    scoring_explanation: str = Field(
        default="",
        description="Human-readable explanation of risk calculation"
    )
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.MEDIUM,
        description="Assessment confidence level"
    )
    
    # NEW: Structured Mitigations
    structured_mitigations: List[StructuredMitigation] = Field(
        default_factory=list,
        description="Structured mitigations with type, status, owner"
    )
    
    # Metadata
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    analysis_id: Optional[str] = None
    
    # Additional fields from existing threats
    scenario: Optional[str] = None  # Legacy scenario field
    specific_mitigations: Optional[List[str]] = None
    references: Optional[List[str]] = None
    threat_agent: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    business_impact: Optional[str] = None
    evidence: Optional[List[Dict[str, str]]] = None
    trust_level: Optional[str] = None
    
    model_config = {"extra": "allow"}
    
    @model_validator(mode="after")
    def ensure_scoring_explanation(self) -> "ThreatEnhanced":
        """Generate scoring explanation if not present"""
        if not self.scoring_explanation and self.dread_score:
            self.scoring_explanation = generate_scoring_explanation(
                self.dread_score, self.overall_risk
            )
        return self
    
    def get_attack_scenario(self) -> AttackScenario:
        """Get attack scenario as a structured object"""
        return AttackScenario(
            preconditions=self.preconditions,
            steps=self.attack_scenario_steps,
            impact_narrative=self.impact_narrative
        )
    
    def get_mitigations_by_type(self) -> Dict[MitigationType, List[StructuredMitigation]]:
        """Group structured mitigations by type"""
        result = {
            MitigationType.PREVENT: [],
            MitigationType.DETECT: [],
            MitigationType.RESPOND: [],
        }
        for m in self.structured_mitigations:
            result[m.mitigation_type].append(m)
        return result


# ===========================================
# API Request/Response Models
# ===========================================

class ThreatCreate(BaseModel):
    """Request model for creating a threat"""
    
    analysis_id: str
    title: str
    description: str
    category: str = "Information Disclosure"
    severity: str = "medium"
    affected_component: str = ""
    attack_vector: str = ""
    mitigations: List[str] = Field(default_factory=list)
    dread_score: Dict[str, float] = Field(
        default_factory=lambda: {
            "damage": 5, "reproducibility": 5, "exploitability": 5,
            "affected_users": 5, "discoverability": 5
        }
    )
    zone: Optional[str] = None
    trust_boundary: Optional[str] = None
    stride_category: str = "I"
    status: str = "identified"
    
    # New fields
    affected_component_ids: List[str] = Field(default_factory=list)
    impacted_flow_ids: List[str] = Field(default_factory=list)
    assets_impacted: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    attack_scenario_steps: List[str] = Field(default_factory=list)
    impact_narrative: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    structured_mitigations: List[StructuredMitigation] = Field(default_factory=list)


class ThreatUpdate(BaseModel):
    """Request model for updating a threat"""
    
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    affected_component: Optional[str] = None
    attack_vector: Optional[str] = None
    mitigations: Optional[List[str]] = None
    dread_score: Optional[Dict[str, float]] = None
    zone: Optional[str] = None
    trust_boundary: Optional[str] = None
    stride_category: Optional[str] = None
    status: Optional[str] = None
    
    # New fields
    affected_component_ids: Optional[List[str]] = None
    impacted_flow_ids: Optional[List[str]] = None
    trust_boundaries: Optional[List[str]] = None
    assets_impacted: Optional[List[str]] = None
    preconditions: Optional[List[str]] = None
    attack_scenario_steps: Optional[List[str]] = None
    impact_narrative: Optional[str] = None
    confidence: Optional[ConfidenceLevel] = None
    structured_mitigations: Optional[List[StructuredMitigation]] = None


class MitigationCreate(BaseModel):
    """Request model for creating a mitigation"""
    
    text: str
    mitigation_type: MitigationType = MitigationType.PREVENT
    status: MitigationStatus = MitigationStatus.PLANNED
    owner: Optional[str] = None
    verification: List[str] = Field(default_factory=list)


class MitigationUpdate(BaseModel):
    """Request model for updating a mitigation"""
    
    text: Optional[str] = None
    mitigation_type: Optional[MitigationType] = None
    status: Optional[MitigationStatus] = None
    owner: Optional[str] = None
    verification: Optional[List[str]] = None


class ThreatDetail(BaseModel):
    """Full threat detail with joined flow map data"""
    
    threat: ThreatEnhanced
    components: List[FlowMapComponent] = Field(default_factory=list)
    flows: List[FlowMapFlow] = Field(default_factory=list)


# ===========================================
# Helper Functions
# ===========================================

def generate_scoring_explanation(
    dread_score: Dict[str, float],
    overall_risk: float
) -> str:
    """Generate a human-readable explanation of the risk score"""
    
    factors = []
    
    d = dread_score.get("damage", 5)
    r = dread_score.get("reproducibility", 5)
    e = dread_score.get("exploitability", 5)
    a = dread_score.get("affected_users", 5)
    disc = dread_score.get("discoverability", 5)
    
    # Highlight significant factors
    if d >= 7:
        factors.append(f"high damage potential ({d}/10)")
    elif d <= 3:
        factors.append(f"limited damage potential ({d}/10)")
    
    if e >= 7:
        factors.append(f"easily exploitable ({e}/10)")
    elif e <= 3:
        factors.append(f"difficult to exploit ({e}/10)")
    
    if a >= 7:
        factors.append(f"affects many users ({a}/10)")
    elif a <= 3:
        factors.append(f"affects few users ({a}/10)")
    
    if r >= 7:
        factors.append(f"highly reproducible ({r}/10)")
    
    if disc >= 7:
        factors.append(f"easily discoverable ({disc}/10)")
    elif disc <= 3:
        factors.append(f"hard to discover ({disc}/10)")
    
    # Build explanation
    if factors:
        factor_text = ", ".join(factors)
        explanation = f"Risk score {overall_risk:.1f}/10 based on DREAD analysis: {factor_text}. "
    else:
        explanation = f"Risk score {overall_risk:.1f}/10 based on balanced DREAD factors. "
    
    explanation += f"Formula: (D{d} + R{r} + E{e} + A{a} + D{disc}) / 5 = {overall_risk:.1f}"
    
    return explanation


def migrate_legacy_threat(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Migrate a legacy threat to the enhanced schema.
    Called during load to ensure backward compatibility.
    """
    # Check if already migrated
    if "structured_mitigations" in threat_data and threat_data["structured_mitigations"]:
        return threat_data
    
    # Create a copy to avoid mutating the original
    migrated = dict(threat_data)
    
    # Set defaults for new fields
    migrated.setdefault("affected_component_ids", [])
    migrated.setdefault("impacted_flow_ids", [])
    migrated.setdefault("trust_boundaries", [])
    migrated.setdefault("assets_impacted", [])
    migrated.setdefault("preconditions", [])
    migrated.setdefault("attack_scenario_steps", [])
    migrated.setdefault("impact_narrative", "")
    migrated.setdefault("scoring_model", "DREAD_AVG_V1")
    migrated.setdefault("confidence", "medium")
    
    # Convert legacy mitigations to structured format
    legacy_mitigations = migrated.get("mitigations", [])
    structured = []
    
    has_detect = False
    has_respond = False
    
    for text in legacy_mitigations:
        if isinstance(text, str):
            mit = StructuredMitigation.from_legacy_string(text)
            structured.append(mit.model_dump())
            if mit.mitigation_type == MitigationType.DETECT:
                has_detect = True
            elif mit.mitigation_type == MitigationType.RESPOND:
                has_respond = True
    
    # Add suggested DETECT mitigation if missing
    if not has_detect and legacy_mitigations:
        structured.append(StructuredMitigation(
            text="Add monitoring and alerting for this threat vector",
            mitigation_type=MitigationType.DETECT,
            status=MitigationStatus.PLANNED,
        ).model_dump())
    
    # Add suggested RESPOND mitigation if missing
    if not has_respond and legacy_mitigations:
        structured.append(StructuredMitigation(
            text="Create incident response runbook for this threat scenario",
            mitigation_type=MitigationType.RESPOND,
            status=MitigationStatus.PLANNED,
        ).model_dump())
    
    migrated["structured_mitigations"] = structured
    
    # Generate scoring explanation if missing
    dread_score = migrated.get("dread_score", {})
    overall_risk = migrated.get("overall_risk", 5.0)
    
    if not migrated.get("scoring_explanation") and dread_score:
        migrated["scoring_explanation"] = generate_scoring_explanation(
            dread_score, overall_risk
        )
    
    # Try to infer affected components from legacy field
    affected = migrated.get("affected_component", "")
    if affected and not migrated.get("affected_component_ids"):
        # Create a simple ID from the component name
        component_id = re.sub(r'[^a-z0-9]+', '_', affected.lower()).strip('_')
        if component_id:
            migrated["affected_component_ids"] = [component_id]
    
    return migrated
