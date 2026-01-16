"""
Security Architect API
Conversational agent endpoints with session management
"""

import json
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from app.agents.security_architect import (
    SecurityArchitectAgent,
    create_security_architect,
)
from app.storage.repository import Repository
from app.config import settings
from app.core.logging import ai_logger

logger = structlog.get_logger()
router = APIRouter()


# ===========================================
# Session Storage
# ===========================================

from pathlib import Path

SESSIONS_DIR = Path(settings.DATA_DIR) / "architect_sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

session_repo = Repository(SESSIONS_DIR, dict)

# In-memory cache for active sessions
_active_sessions: Dict[str, SecurityArchitectAgent] = {}


async def get_or_create_session(session_id: str = None) -> SecurityArchitectAgent:
    """Get existing session or create new one"""
    if session_id and session_id in _active_sessions:
        return _active_sessions[session_id]
    
    if session_id:
        # Try to load from storage
        data = await session_repo.load(session_id)
        if data:
            agent = SecurityArchitectAgent.from_dict(data)
            _active_sessions[session_id] = agent
            return agent
    
    # Create new session
    agent = create_security_architect(session_id)
    _active_sessions[agent.session_id] = agent
    return agent


async def save_session(agent: SecurityArchitectAgent):
    """Persist session to storage"""
    await session_repo.save(agent.session_id, agent.to_dict())


# ===========================================
# Models
# ===========================================

class ChatMessage(BaseModel):
    """User message to the architect"""
    message: str = Field(..., min_length=1, max_length=10000)
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    """Response from the architect"""
    response: str
    response_type: str  # question, confirm, warning, summary, complete
    session_id: str
    thinking: Optional[str] = None  # CoT reasoning (can be hidden)
    assumptions: list = Field(default_factory=list)
    world_model_summary: Dict[str, Any] = Field(default_factory=dict)
    completion_score: float = 0.0
    topics_covered: list = Field(default_factory=list)
    topics_pending: list = Field(default_factory=list)
    suggested_actions: list = Field(default_factory=list)


class SessionSummary(BaseModel):
    """Summary of a session for recovery"""
    session_id: str
    created_at: str
    updated_at: str
    completion_score: float
    architecture_type: str
    topics_covered: list
    conversation_turns: int
    summary_text: str


class WorldModelExport(BaseModel):
    """Export of the world model"""
    session_id: str
    world_model: Dict[str, Any]
    conversation_history: list


# ===========================================
# Endpoints
# ===========================================

@router.post("/chat", response_model=ChatResponse)
async def chat(message: ChatMessage):
    """
    Send a message to the Security Architect agent.
    
    The agent will:
    1. Analyze your input using Chain-of-Thought reasoning
    2. Update its internal world model
    3. Respond with contextual questions or confirmations
    
    You can send:
    - Natural language descriptions
    - Code snippets (e.g., server.js, package.json)
    - Configuration files (docker-compose, etc.)
    - JSON architecture definitions
    """
    agent = await get_or_create_session(message.session_id)
    
    # Log interaction
    ai_logger.log_agent_action(
        agent_name="security_architect",
        action="chat",
        project_id=agent.session_id,
        message_length=len(message.message)
    )
    
    try:
        result = await agent.process_message(message.message)
        
        # Save session
        await save_session(agent)
        
        # Build world model summary (safe for frontend)
        wm = agent.world_model
        wm_summary = {
            "architecture_type": wm.architecture_type,
            "tech_stack": {
                k: {"value": v.get("framework") or v.get("provider"), "confirmed": v.get("confirmed", False)}
                for k, v in wm.tech_stack.items()
                if v.get("framework") or v.get("provider")
            },
            "components_count": len(wm.components),
            "data_sensitivity": wm.data_sensitivity,
            "compliance": wm.compliance_requirements,
        }
        
        return ChatResponse(
            response=result["response"],
            response_type=result["response_type"],
            session_id=agent.session_id,
            thinking=result.get("thinking"),
            assumptions=result.get("assumptions", []),
            world_model_summary=wm_summary,
            completion_score=result["completion_score"],
            topics_covered=result["topics_covered"],
            topics_pending=result["topics_pending"],
            suggested_actions=result.get("suggested_actions", []),
        )
        
    except Exception as e:
        logger.error("Architect chat failed", error=str(e), session_id=agent.session_id)
        raise HTTPException(500, f"Failed to process message: {str(e)}")


@router.post("/start")
async def start_session():
    """Start a new architect session"""
    agent = await get_or_create_session()
    await save_session(agent)
    
    # Generate welcome message
    welcome = """👋 **Hello! I'm your Security Architect.**

I'll help you build a comprehensive threat model for your application. 

**How this works:**
1. Describe your system - architecture, tech stack, data flows
2. I'll ask smart follow-up questions (and skip irrelevant ones)
3. You can paste code snippets or configs - I'll parse them automatically
4. We'll build a complete security model together

**Let's start:** What are you building? 
_(e.g., "A Next.js e-commerce app on Vercel with Stripe payments")_"""
    
    return {
        "session_id": agent.session_id,
        "message": welcome,
        "response_type": "welcome",
    }


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get session status and summary"""
    agent = await get_or_create_session(session_id)
    
    return SessionSummary(
        session_id=agent.session_id,
        created_at=agent.world_model.created_at,
        updated_at=agent.world_model.updated_at,
        completion_score=agent.world_model.completion_score,
        architecture_type=agent.world_model.architecture_type,
        topics_covered=agent.world_model.topics_covered,
        conversation_turns=agent.world_model.conversation_turns,
        summary_text=agent.get_session_summary(),
    )


@router.get("/session/{session_id}/recover")
async def recover_session(session_id: str):
    """
    Recover a previous session with a summary.
    Use this when a user returns after dropping off.
    """
    agent = await get_or_create_session(session_id)
    summary = agent.get_session_summary()
    
    return {
        "session_id": agent.session_id,
        "message": summary,
        "response_type": "recovery",
        "completion_score": agent.world_model.completion_score,
        "can_continue": agent.world_model.completion_score < 1.0,
    }


@router.get("/session/{session_id}/world-model")
async def get_world_model(session_id: str):
    """Get the current world model (architecture representation)"""
    agent = await get_or_create_session(session_id)
    
    return WorldModelExport(
        session_id=agent.session_id,
        world_model=agent.to_dict()["world_model"],
        conversation_history=agent.conversation_history,
    )


@router.post("/session/{session_id}/confirm")
async def confirm_assumption(session_id: str, assumption_index: int, confirmed: bool):
    """Confirm or deny an assumption made by the agent"""
    agent = await get_or_create_session(session_id)
    
    if assumption_index < len(agent.world_model.assumptions):
        agent.world_model.assumptions[assumption_index]["confirmed"] = confirmed
        agent.world_model.assumptions[assumption_index]["confidence"] = 1.0 if confirmed else 0.0
        await save_session(agent)
        
        return {"status": "updated", "assumption": agent.world_model.assumptions[assumption_index]}
    
    raise HTTPException(404, "Assumption not found")


@router.post("/session/{session_id}/generate")
async def generate_threat_model(session_id: str):
    """
    Generate threat model from the current world model.
    Requires sufficient completion (>60%).
    """
    agent = await get_or_create_session(session_id)
    
    if agent.world_model.completion_score < 0.6:
        raise HTTPException(
            400, 
            f"Model is only {agent.world_model.completion_score:.0%} complete. "
            "Please provide more information before generating."
        )
    
    # Here we would integrate with the existing threat modeling pipeline
    # For now, return the world model data that can be used
    return {
        "session_id": session_id,
        "ready": True,
        "world_model": agent.to_dict()["world_model"],
        "next_step": "Call /api/analyze with this world model to generate threats",
    }


@router.get("/sessions")
async def list_sessions():
    """List all saved sessions"""
    session_ids = await session_repo.list_ids()
    sessions = []
    
    for sid in session_ids[:20]:  # Limit to 20
        data = await session_repo.load(sid)
        if data:
            wm = data.get("world_model", {})
            sessions.append({
                "session_id": sid,
                "created_at": wm.get("created_at"),
                "updated_at": wm.get("updated_at"),
                "completion_score": wm.get("completion_score", 0),
                "architecture_type": wm.get("architecture_type", "unknown"),
                "conversation_turns": wm.get("conversation_turns", 0),
            })
    
    return {"sessions": sorted(sessions, key=lambda s: s.get("updated_at", ""), reverse=True)}


@router.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a session"""
    if session_id in _active_sessions:
        del _active_sessions[session_id]
    
    await session_repo.delete(session_id)
    
    return {"status": "deleted", "session_id": session_id}


# ===========================================
# Form-based Analysis (from Architect questionnaire)
# ===========================================

class ArchitectFormData(BaseModel):
    """Data collected from the architect form"""
    methodology: str = "stride"
    architecture_type: Any = None
    system_description: Optional[str] = None
    components: Optional[str] = None
    uses_ai: Optional[str] = None
    ai_type: Optional[str] = None
    ai_provider: Optional[str] = None
    ai_data_handling: Optional[str] = None
    ai_security_concerns: Optional[str] = None
    data_types: Any = None
    data_storage: Any = None
    data_flow_description: Optional[str] = None
    auth_method: Any = None
    auth_provider: Any = None
    authorization: Any = None
    network_exposure: Optional[str] = None
    encryption: Any = None
    secrets_management: Any = None
    logging_monitoring: Any = None
    compliance_frameworks: Any = None
    security_concerns: Optional[str] = None
    additional_info: Optional[str] = None
    # Custom fields
    architecture_type_custom: Optional[str] = None
    auth_method_custom: Optional[str] = None


@router.post("/analyze-form")
async def analyze_from_form(form_data: ArchitectFormData):
    """
    Analyze architecture from the questionnaire form data.
    Creates a project and runs threat analysis.
    """
    from app.storage.repository import project_repo, analysis_repo
    
    # Generate IDs
    project_id = str(uuid.uuid4())
    analysis_id = str(uuid.uuid4())
    
    # Normalize arrays
    def normalize_list(val):
        if isinstance(val, list):
            return val
        if isinstance(val, str):
            return [val] if val else []
        return []
    
    architecture_types = normalize_list(form_data.architecture_type)
    data_types = normalize_list(form_data.data_types)
    auth_methods = normalize_list(form_data.auth_method)
    compliance = normalize_list(form_data.compliance_frameworks)
    
    # Build system description for analysis
    system_desc = f"""
System Type: {', '.join(architecture_types) if architecture_types else 'Not specified'}
Description: {form_data.system_description or 'Not provided'}
Components: {form_data.components or 'Not specified'}

AI/ML: {form_data.uses_ai or 'Not specified'}
{f'AI Type: {form_data.ai_type}' if form_data.ai_type else ''}
{f'AI Provider: {form_data.ai_provider}' if form_data.ai_provider else ''}

Data Types: {', '.join(data_types) if data_types else 'Not specified'}
Data Storage: {', '.join(normalize_list(form_data.data_storage)) if form_data.data_storage else 'Not specified'}
Data Flow: {form_data.data_flow_description or 'Not specified'}

Authentication: {', '.join(auth_methods) if auth_methods else 'Not specified'}
Authorization: {', '.join(normalize_list(form_data.authorization)) if form_data.authorization else 'Not specified'}

Network Exposure: {form_data.network_exposure or 'Not specified'}
Encryption: {', '.join(normalize_list(form_data.encryption)) if form_data.encryption else 'Not specified'}
Secrets Management: {', '.join(normalize_list(form_data.secrets_management)) if form_data.secrets_management else 'Not specified'}

Compliance Requirements: {', '.join(compliance) if compliance else 'None specified'}
Security Concerns: {form_data.security_concerns or 'None specified'}
Additional Context: {form_data.additional_info or 'None'}
""".strip()

    # Create project record
    project_data = {
        "id": project_id,
        "name": f"Security Review - {form_data.system_description[:50] if form_data.system_description else 'Unnamed'}...",
        "description": system_desc,
        "created_at": datetime.utcnow().isoformat(),
        "source": "architect_form",
        "architecture_types": architecture_types,
        "methodology": form_data.methodology,
    }
    await project_repo.save(project_id, project_data)
    
    # Generate threats based on architecture and methodology
    threats = _generate_threats_for_architecture(form_data, architecture_types, data_types, auth_methods, compliance)
    
    # Generate basic DFD
    dfd_mermaid = _generate_dfd(form_data, architecture_types)
    
    # Generate compliance summary
    compliance_summary = _generate_compliance_summary(threats, compliance)
    
    # Build analysis result
    analysis_data = {
        "id": analysis_id,
        "project_id": project_id,
        "methodology": form_data.methodology,
        "status": "completed",
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_threats": len(threats),
            "critical": len([t for t in threats if t.get("severity") == "critical"]),
            "high": len([t for t in threats if t.get("severity") == "high"]),
            "medium": len([t for t in threats if t.get("severity") == "medium"]),
            "low": len([t for t in threats if t.get("severity") == "low"]),
            "architecture_types": architecture_types,
            "data_types": data_types,
        },
        "threats": threats,
        "dfd_mermaid": dfd_mermaid,
        "compliance_summary": compliance_summary,
        "source_data": form_data.dict(),
    }
    await analysis_repo.save(analysis_id, analysis_data)
    
    logger.info("form_analysis_complete", project_id=project_id, analysis_id=analysis_id, threats_count=len(threats))
    
    return {
        "success": True,
        "project_id": project_id,
        "analysis_id": analysis_id,
        "threats_count": len(threats),
        "summary": analysis_data["summary"],
        "redirect_url": f"/review?analysis_id={analysis_id}",
    }


def _generate_threats_for_architecture(form_data, architecture_types, data_types, auth_methods, compliance):
    """Generate comprehensive threats based on the architecture"""
    threats = []
    threat_id = 0
    
    # STRIDE-based threats
    stride_threats = [
        # Spoofing
        {
            "category": "Spoofing",
            "stride_category": "S",
            "title": "Authentication Bypass",
            "description": "Attacker may bypass authentication mechanisms to impersonate legitimate users",
            "affected_component": "Authentication System",
            "attack_vector": "Credential stuffing, brute force, session hijacking, token theft",
            "severity": "high",
            "mitigations": [
                "Implement multi-factor authentication (MFA)",
                "Use secure session management",
                "Enforce strong password policies",
                "Implement account lockout after failed attempts",
                "Use secure token storage"
            ]
        },
        {
            "category": "Spoofing",
            "stride_category": "S",
            "title": "API Key Compromise",
            "description": "API keys or service credentials may be compromised and used for unauthorized access",
            "affected_component": "API Gateway",
            "attack_vector": "Key exposure in logs, source code, or client-side storage",
            "severity": "high",
            "mitigations": [
                "Rotate API keys regularly",
                "Never expose keys in client-side code",
                "Use secrets management solutions",
                "Implement key scoping and least privilege"
            ]
        },
        # Tampering
        {
            "category": "Tampering",
            "stride_category": "T",
            "title": "Data Manipulation in Transit",
            "description": "Attacker may intercept and modify data as it flows between components",
            "affected_component": "Network Communication",
            "attack_vector": "Man-in-the-middle attacks, SSL stripping",
            "severity": "high",
            "mitigations": [
                "Enforce TLS 1.3 for all communications",
                "Implement certificate pinning",
                "Use HSTS headers",
                "Validate data integrity with checksums"
            ]
        },
        {
            "category": "Tampering",
            "stride_category": "T",
            "title": "SQL/NoSQL Injection",
            "description": "Attacker may inject malicious queries to manipulate or extract database data",
            "affected_component": "Database Layer",
            "attack_vector": "Unsanitized user input in database queries",
            "severity": "critical",
            "mitigations": [
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege for database accounts",
                "Use ORM frameworks with built-in protection"
            ]
        },
        # Repudiation
        {
            "category": "Repudiation",
            "stride_category": "R",
            "title": "Insufficient Audit Logging",
            "description": "System may lack sufficient logging to attribute actions to specific users",
            "affected_component": "Logging System",
            "attack_vector": "Absence of audit trail allows denial of malicious actions",
            "severity": "medium",
            "mitigations": [
                "Implement comprehensive audit logging",
                "Log all authentication and authorization events",
                "Use centralized, tamper-proof log storage",
                "Include timestamps, user IDs, and IP addresses"
            ]
        },
        # Information Disclosure
        {
            "category": "Information Disclosure",
            "stride_category": "I",
            "title": "Sensitive Data Exposure",
            "description": "Sensitive information may be exposed through APIs, logs, or error messages",
            "affected_component": "API/Application Layer",
            "attack_vector": "Verbose error messages, API enumeration, log exposure",
            "severity": "high",
            "mitigations": [
                "Implement proper error handling without sensitive details",
                "Mask PII in logs",
                "Use data classification and protection",
                "Implement rate limiting on APIs"
            ]
        },
        {
            "category": "Information Disclosure",
            "stride_category": "I",
            "title": "Insecure Data Storage",
            "description": "Data at rest may be accessible to unauthorized parties",
            "affected_component": "Database/Storage",
            "attack_vector": "Unencrypted storage, weak access controls",
            "severity": "high",
            "mitigations": [
                "Encrypt data at rest using AES-256",
                "Implement proper access controls",
                "Use hardware security modules (HSM) for keys",
                "Regular security assessments"
            ]
        },
        # Denial of Service
        {
            "category": "Denial of Service",
            "stride_category": "D",
            "title": "Resource Exhaustion",
            "description": "Attacker may exhaust system resources causing service unavailability",
            "affected_component": "Application Server",
            "attack_vector": "DDoS, algorithmic complexity attacks, resource-intensive requests",
            "severity": "medium",
            "mitigations": [
                "Implement rate limiting",
                "Use CDN and DDoS protection",
                "Set resource quotas and timeouts",
                "Implement circuit breakers"
            ]
        },
        # Elevation of Privilege
        {
            "category": "Elevation of Privilege",
            "stride_category": "E",
            "title": "Broken Access Control",
            "description": "Attacker may access resources or functions beyond their authorization level",
            "affected_component": "Authorization System",
            "attack_vector": "IDOR, privilege escalation, missing function-level access control",
            "severity": "critical",
            "mitigations": [
                "Implement role-based access control (RBAC)",
                "Deny by default, allow explicitly",
                "Validate authorization on every request",
                "Regular access control audits"
            ]
        },
    ]
    
    # Add data-type specific threats
    if any(d in ['pii', 'user_credentials', 'phi', 'financial'] for d in data_types):
        stride_threats.append({
            "category": "Information Disclosure",
            "stride_category": "I",
            "title": "Personal Data Breach",
            "description": "Personal or sensitive data may be exposed leading to regulatory violations",
            "affected_component": "Data Processing Layer",
            "attack_vector": "SQL injection, misconfigured access, insider threats",
            "severity": "critical",
            "mitigations": [
                "Implement data encryption at rest and in transit",
                "Apply data masking/tokenization",
                "Enforce strict access controls",
                "Regular data protection impact assessments"
            ]
        })
    
    # Add AI-specific threats if applicable
    if form_data.uses_ai and form_data.uses_ai != "no":
        stride_threats.extend([
            {
                "category": "AI Security",
                "stride_category": "T",
                "title": "Prompt Injection",
                "description": "Attacker may manipulate AI model behavior through crafted malicious prompts",
                "affected_component": "AI/LLM System",
                "attack_vector": "Crafted prompts, jailbreaking, indirect injection via data",
                "severity": "high",
                "mitigations": [
                    "Implement input validation and sanitization",
                    "Use prompt templates with proper escaping",
                    "Limit model capabilities through system prompts",
                    "Monitor and log AI interactions"
                ]
            },
            {
                "category": "AI Security",
                "stride_category": "I",
                "title": "Model Data Leakage",
                "description": "AI model may leak training data or sensitive information through outputs",
                "affected_component": "AI/LLM System",
                "attack_vector": "Prompt extraction, membership inference, model inversion",
                "severity": "medium",
                "mitigations": [
                    "Use differential privacy during training",
                    "Implement output filtering",
                    "Regular model security assessments",
                    "Avoid training on sensitive data directly"
                ]
            },
            {
                "category": "AI Security",
                "stride_category": "T",
                "title": "Model Manipulation/Poisoning",
                "description": "Training data or model weights may be manipulated to cause malicious behavior",
                "affected_component": "AI Training Pipeline",
                "attack_vector": "Data poisoning, adversarial examples, supply chain attacks",
                "severity": "high",
                "mitigations": [
                    "Validate and sanitize training data",
                    "Implement model integrity checking",
                    "Use adversarial training techniques",
                    "Secure the ML pipeline"
                ]
            }
        ])
    
    # Add web app specific threats
    if 'web_app' in architecture_types:
        stride_threats.extend([
            {
                "category": "Tampering",
                "stride_category": "T",
                "title": "Cross-Site Scripting (XSS)",
                "description": "Attacker may inject malicious scripts that execute in users' browsers",
                "affected_component": "Web Frontend",
                "attack_vector": "Stored/reflected XSS through user input",
                "severity": "high",
                "mitigations": [
                    "Implement Content Security Policy (CSP)",
                    "Escape output properly",
                    "Use modern frameworks with built-in XSS protection",
                    "Input validation and sanitization"
                ]
            },
            {
                "category": "Spoofing",
                "stride_category": "S",
                "title": "Cross-Site Request Forgery (CSRF)",
                "description": "Attacker may trick users into performing unintended actions",
                "affected_component": "Web Application",
                "attack_vector": "Malicious links or forms submitted from attacker-controlled sites",
                "severity": "medium",
                "mitigations": [
                    "Implement CSRF tokens",
                    "Use SameSite cookie attribute",
                    "Verify Origin/Referer headers",
                    "Require re-authentication for sensitive operations"
                ]
            }
        ])
    
    # Add API specific threats
    if 'api' in architecture_types or 'microservices' in architecture_types:
        stride_threats.append({
            "category": "Information Disclosure",
            "stride_category": "I",
            "title": "API Data Over-exposure",
            "description": "APIs may return more data than necessary exposing sensitive information",
            "affected_component": "API Endpoints",
            "attack_vector": "Mass assignment, excessive data exposure in responses",
            "severity": "medium",
            "mitigations": [
                "Implement response filtering",
                "Use GraphQL with proper field authorization",
                "Apply data transfer object (DTO) patterns",
                "Regular API security reviews"
            ]
        })
    
    # Build final threat list with IDs and risk scores
    for threat in stride_threats:
        threat_id += 1
        severity = threat.get("severity", "medium")
        risk_score = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0}.get(severity, 5.0)
        
        threats.append({
            "id": f"THREAT-{threat_id:03d}",
            **threat,
            "overall_risk": risk_score,
            "dread_score": {
                "damage": min(10, risk_score + 1),
                "reproducibility": 6,
                "exploitability": 5,
                "affected_users": 7,
                "discoverability": 5
            },
            "compliance_mappings": _get_compliance_mappings(threat["category"], compliance),
            "status": "open"
        })
    
    return threats


def _get_compliance_mappings(category: str, frameworks: list) -> dict:
    """Map threat category to compliance controls"""
    mappings = {
        "Spoofing": {
            "NIST_800_53": ["IA-2", "IA-5", "IA-8", "AC-3"],
            "OWASP_ASVS": ["V2.1", "V2.2", "V2.7", "V3.2"]
        },
        "Tampering": {
            "NIST_800_53": ["SC-8", "SC-13", "SI-7", "SI-10"],
            "OWASP_ASVS": ["V5.1", "V5.2", "V5.3", "V6.2"]
        },
        "Repudiation": {
            "NIST_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "OWASP_ASVS": ["V7.1", "V7.2", "V7.4"]
        },
        "Information Disclosure": {
            "NIST_800_53": ["SC-28", "SC-8", "AC-4", "MP-4"],
            "OWASP_ASVS": ["V6.1", "V8.1", "V8.2", "V9.1"]
        },
        "Denial of Service": {
            "NIST_800_53": ["SC-5", "CP-9", "CP-10", "SI-17"],
            "OWASP_ASVS": ["V11.1", "V11.2"]
        },
        "Elevation of Privilege": {
            "NIST_800_53": ["AC-2", "AC-3", "AC-5", "AC-6"],
            "OWASP_ASVS": ["V4.1", "V4.2", "V4.3"]
        },
        "AI Security": {
            "NIST_800_53": ["SA-15", "SI-10", "SC-28", "AC-4"],
            "OWASP_ASVS": ["V1.1", "V5.1", "V8.1"]
        }
    }
    
    result = {}
    cat_mapping = mappings.get(category, mappings.get("Information Disclosure"))
    for fw in frameworks:
        if fw in cat_mapping:
            result[fw] = cat_mapping[fw]
    
    return result if result else {"NIST_800_53": ["AC-1"], "OWASP_ASVS": ["V1.1"]}


def _generate_dfd(form_data, architecture_types):
    """Generate a Mermaid DFD diagram"""
    components = []
    if form_data.components:
        components = [c.strip() for c in form_data.components.split(',') if c.strip()]
    
    # Build basic DFD
    lines = ["flowchart TD"]
    lines.append("    subgraph External[External Entities]")
    lines.append("        User[\"👤 User\"]")
    lines.append("        Admin[\"👤 Admin\"]")
    lines.append("    end")
    
    if 'web_app' in architecture_types or 'api' in architecture_types:
        lines.append("    subgraph Frontend[Frontend Tier]")
        lines.append("        WebApp[\"🌐 Web Application\"]")
        lines.append("    end")
    
    lines.append("    subgraph Backend[Backend Tier]")
    if components:
        for i, comp in enumerate(components[:5]):  # Limit to 5 components
            lines.append(f"        Comp{i}[\"{comp}\"]")
    else:
        lines.append("        API[\"⚙️ API Server\"]")
        lines.append("        Auth[\"🔐 Auth Service\"]")
    lines.append("    end")
    
    lines.append("    subgraph Data[Data Tier]")
    lines.append("        DB[(\"🗄️ Database\")]")
    if form_data.uses_ai and form_data.uses_ai != "no":
        lines.append("        AI[\"🤖 AI/ML Service\"]")
    lines.append("    end")
    
    # Add flows
    lines.append("")
    lines.append("    User --> WebApp")
    lines.append("    Admin --> WebApp")
    
    if 'web_app' in architecture_types:
        if components:
            lines.append(f"    WebApp --> Comp0")
        else:
            lines.append("    WebApp --> API")
            lines.append("    API --> Auth")
            lines.append("    API --> DB")
    
    if form_data.uses_ai and form_data.uses_ai != "no":
        if components:
            lines.append(f"    Comp0 --> AI")
        else:
            lines.append("    API --> AI")
    
    return "\n".join(lines)


def _generate_compliance_summary(threats, frameworks):
    """Generate compliance summary from threats"""
    summary = {}
    
    for fw in frameworks:
        controls = set()
        for threat in threats:
            mappings = threat.get("compliance_mappings", {})
            if fw in mappings:
                controls.update(mappings[fw])
        
        summary[fw] = {
            "framework": fw,
            "controls_identified": len(controls),
            "controls": sorted(list(controls)),
            "coverage_status": "partial"
        }
    
    return summary


