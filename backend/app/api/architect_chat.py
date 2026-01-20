"""
Intelligent Security Architect Chat API
AI-driven conversation for threat modeling with LLM analysis
Implements Grounded Responses and Thinking Time Control
"""

import json
import uuid
import re
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from app.services.llm_provider import get_llm_provider
from app.services.web_search import get_web_search_service, SearchResult
from app.services.reasoning import get_reasoning_service, ReasoningLevel, ReasoningSummary
from app.api.settings import get_runtime_config
from app.storage.repository import project_repo, analysis_repo
from app.config import settings
from pathlib import Path

logger = structlog.get_logger()
router = APIRouter()

# Session storage
SESSIONS_DIR = Path(settings.DATA_DIR) / "chat_sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================
# System Prompts (Grounded Response Policy)
# ===========================================

# Base system prompt with anti-hallucination rules
GROUNDED_SYSTEM_PROMPT_BASE = """You are an expert Security Architect AI assistant specializing in threat modeling.

## CRITICAL GROUNDING RULES (MUST FOLLOW):
1. NEVER invent relationships between frameworks (e.g., NEVER say "STRIDE is part of PASTA" unless you have verified sources)
2. NEVER make up standards, version numbers, or links
3. For DEFINITION questions (e.g., "what is STRIDE"), answer DIRECTLY with the definition - do NOT ask follow-up questions about their system
4. For THREAT MODELING requests, ask focused questions about their specific system
5. When uncertain about a fact, explicitly say "I'm not certain about this"
6. NEVER claim to have checked online or verified facts when web search is disabled

## Question Types - How to Respond:
- DEFINITION/CONCEPTUAL (e.g., "what is X", "explain Y", "difference between A and B"):
  → Answer directly with accurate information. No follow-up questions needed.
  
- THREAT MODELING REQUEST (e.g., "analyze my system", "create threat model for..."):
  → Ask focused questions about their specific architecture, data flows, auth, etc.

- COMPARISON (e.g., "STRIDE vs PASTA"):
  → Compare factually. State only what you know with certainty. Admit gaps.
"""

# Prompt suffix for LOCAL mode (no web search)
LOCAL_MODE_SUFFIX = """
## LOCAL MODE ACTIVE (No Web Search):
- Answer using your training knowledge
- DO NOT claim to have verified information online
- If uncertain about specific details, versions, or recent changes, say so explicitly
- Add a brief note when your information might be outdated
"""

# Prompt suffix for WEB-GROUNDED mode
WEB_GROUNDED_SUFFIX = """
## WEB-GROUNDED MODE ACTIVE:
- You have access to web search results provided below
- Base your factual claims ONLY on the search results provided
- ALWAYS cite sources with [Source Title](URL) format
- If search results don't cover a topic, say "Based on my search, I couldn't find specific information about..."
- Include a "Sources" section at the end with 2-5 relevant links
"""

SECURITY_ARCHITECT_SYSTEM = GROUNDED_SYSTEM_PROMPT_BASE + """
## For Threat Modeling Conversations:

Your role is to:
1. ANALYZE the user's input about their system/architecture
2. IDENTIFY what information is missing or unclear
3. ASK focused follow-up questions to gather complete context
4. DETERMINE when you have enough information to generate a threat model

## Information You Need to Gather (for threat modeling):
- System type (web app, API, microservices, data pipeline, etc.)
- Main components and their interactions
- Data types being processed (PII, credentials, financial, healthcare, etc.)
- Authentication and authorization mechanisms
- Network exposure (public internet, internal, VPN, etc.)
- Third-party integrations
- Compliance requirements (GDPR, HIPAA, PCI-DSS, SOC2, etc.)
- AI/ML components if any (LLMs, ML models, training data)

## Chain-of-Thought Reasoning (REQUIRED):
Before providing your final answer, you MUST think through the problem step by step.
Show your reasoning process inside <thinking> tags BEFORE the JSON response.

Example format:
<thinking>
1. Understanding the question: [what the user is asking]
2. Key considerations: [relevant factors to analyze]
3. Analysis approach: [how you'll analyze this]
4. Reasoning steps:
   - First, I notice...
   - This suggests...
   - Considering the security implications...
5. Conclusion: [your determination]
</thinking>

{your JSON response here}

IMPORTANT: The <thinking> block must come BEFORE your JSON response. This shows your reasoning process.

## Response Format:
Always respond with valid JSON in this exact format:
{
    "response_type": "definition|threat_modeling|comparison|general",
    "analysis": "Your analysis/answer",
    "completeness_score": 0.0-1.0,
    "missing_info": ["list of missing critical information"],
    "follow_up_questions": ["specific questions - ONLY for threat modeling, NOT for definitions"],
    "ready_for_threat_model": true/false,
    "confidence_level": "high|medium|low",
    "uncertainty_notes": ["things you're not certain about"],
    "world_model": {
        "system_type": "identified system type",
        "components": ["list of identified components"],
        "data_types": ["identified data types"],
        "auth_method": "identified auth method",
        "network_exposure": "public/internal/hybrid",
        "compliance": ["identified compliance requirements"],
        "ai_involved": true/false
    },
    "sources": []
}

## Rules:
- For definitions: Set response_type="definition", completeness_score=1.0, NO follow_up_questions
- For threat modeling: Ask 2-3 questions at a time maximum
- Set ready_for_threat_model to true only when completeness_score >= 0.7 AND response_type="threat_modeling"
- Be honest about uncertainty - set confidence_level appropriately
"""


THREAT_GENERATION_PROMPT = """Based on the following system context, generate a comprehensive STRIDE threat model with detailed mitigations and test cases.

## System Context:
{context}

## Requirements:
Generate threats for each STRIDE category that applies:
- Spoofing (authentication bypass, impersonation)
- Tampering (data modification, injection attacks)
- Repudiation (audit logging gaps)
- Information Disclosure (data leaks, exposure)
- Denial of Service (availability attacks)
- Elevation of Privilege (authorization bypass)

## OWASP Framework Mappings (REQUIRED):
For each threat, map to relevant OWASP frameworks:

### OWASP Top 10 Web (2021):
- A01:2021 Broken Access Control
- A02:2021 Cryptographic Failures
- A03:2021 Injection
- A04:2021 Insecure Design
- A05:2021 Security Misconfiguration
- A06:2021 Vulnerable Components
- A07:2021 Authentication Failures
- A08:2021 Software/Data Integrity Failures
- A09:2021 Logging/Monitoring Failures
- A10:2021 SSRF

### OWASP API Security Top 10 (2023) - if API is involved:
- API1:2023 Broken Object Level Authorization
- API2:2023 Broken Authentication
- API3:2023 Broken Property Level Authorization
- API4:2023 Unrestricted Resource Consumption
- API5:2023 Broken Function Level Authorization
- API6:2023 Unrestricted Business Flows
- API7:2023 Server Side Request Forgery
- API8:2023 Security Misconfiguration
- API9:2023 Improper Inventory Management
- API10:2023 Unsafe API Consumption

### OWASP LLM AI Top 10 (2025) - if AI/LLM components exist:
- LLM01:2025 Prompt Injection
- LLM02:2025 Sensitive Information Disclosure
- LLM03:2025 Supply Chain Vulnerabilities
- LLM04:2025 Data and Model Poisoning
- LLM05:2025 Improper Output Handling
- LLM06:2025 Excessive Agency
- LLM07:2025 System Prompt Leakage
- LLM08:2025 Vector and Embedding Weaknesses
- LLM09:2025 Misinformation/Hallucination
- LLM10:2025 Unbounded Consumption

### Agentic AI Security - if AI agents/autonomous systems exist:
- AGENT01 Uncontrolled Agent Autonomy
- AGENT02 Tool/API Abuse by Agents
- AGENT03 Agent Memory Manipulation
- AGENT04 Multi-Agent Coordination Attacks
- AGENT05 Goal Misalignment

For each threat, provide:
1. Clear description of the threat
2. Attack vector and prerequisites
3. Impact assessment (DREAD scores)
4. Detailed mitigations with implementation steps
5. Test cases to validate the mitigations
6. OWASP framework mappings

## Response Format:
Return valid JSON:
{{
    "methodology": "STRIDE",
    "ai_components_detected": true/false,
    "agent_components_detected": true/false,
    "api_exposed": true/false,
    "threats": [
        {{
            "id": "THREAT-001",
            "category": "Spoofing",
            "title": "Clear threat title",
            "description": "Detailed description",
            "attack_vector": "How the attack works",
            "prerequisites": ["What attacker needs"],
            "affected_component": "Component name",
            "severity": "critical/high/medium/low",
            "likelihood": "high/medium/low",
            "impact": "Description of impact",
            "dread_score": {{
                "damage": 1-10,
                "reproducibility": 1-10,
                "exploitability": 1-10,
                "affected_users": 1-10,
                "discoverability": 1-10
            }},
            "mitigations": [
                {{
                    "id": "MIT-001",
                    "title": "Mitigation title",
                    "description": "Detailed mitigation steps",
                    "implementation_steps": [
                        "Step 1: ...",
                        "Step 2: ..."
                    ],
                    "priority": "critical/high/medium/low",
                    "effort": "low/medium/high",
                    "test_cases": [
                        {{
                            "id": "TC-001",
                            "title": "Test case title",
                            "description": "What to test",
                            "steps": ["Step 1", "Step 2"],
                            "expected_result": "Expected outcome",
                            "tools": ["Suggested tools"]
                        }}
                    ]
                }}
            ],
            "owasp_mappings": {{
                "owasp_top_10": ["A01:2021", "A03:2021"],
                "owasp_api": ["API1:2023"],
                "owasp_llm": ["LLM01:2025"],
                "agentic_ai": ["AGENT01"]
            }},
            "compliance_mappings": {{
                "NIST_800_53": ["Control IDs"],
                "OWASP_ASVS": ["Requirement IDs"]
            }}
        }}
    ],
    "ai_specific_threats": [
        {{
            "id": "AI-THREAT-001",
            "owasp_id": "LLM01:2025",
            "title": "Prompt Injection via User Input",
            "description": "Detailed AI-specific threat",
            "attack_vector": "How AI component can be exploited",
            "mitigations": ["AI-specific mitigations"]
        }}
    ],
    "recommendations": ["High-level security recommendations"],
    "dfd_description": "Description for DFD generation"
}}"""


# ===========================================
# Models
# ===========================================

class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)
    session_id: Optional[str] = None
    web_search_enabled: bool = Field(default=False, description="Enable web search for grounded responses")
    reasoning_level: str = Field(default="balanced", description="Reasoning depth: fast, balanced, deep")


class ChatResponse(BaseModel):
    session_id: str
    response: str
    analysis: Optional[str] = None
    completeness_score: float = 0.0
    missing_info: List[str] = []
    follow_up_questions: List[str] = []
    ready_for_threat_model: bool = False
    world_model: Dict[str, Any] = {}
    conversation_history: List[Dict] = []
    web_search_used: bool = False
    sources: List[Dict[str, str]] = []
    confidence_level: str = "high"
    reasoning_summary: Optional[Dict[str, Any]] = None
    reasoning_level: str = "balanced"
    thinking: Optional[str] = None  # Chain-of-thought reasoning from LLM


class GenerateRequest(BaseModel):
    session_id: str


class ThreatModelResponse(BaseModel):
    success: bool
    analysis_id: str
    project_id: str
    threats_count: int
    threats: List[Dict]
    summary: Dict
    dfd_mermaid: str
    recommendations: List[str]


# ===========================================
# Session Management
# ===========================================

async def load_session(session_id: str) -> Optional[Dict]:
    """Load session from storage"""
    session_file = SESSIONS_DIR / f"{session_id}.json"
    if session_file.exists():
        with open(session_file, 'r') as f:
            return json.load(f)
    return None


async def save_session(session_id: str, data: Dict):
    """Save session to storage"""
    session_file = SESSIONS_DIR / f"{session_id}.json"
    with open(session_file, 'w') as f:
        json.dump(data, f, indent=2, default=str)


async def list_sessions() -> List[Dict]:
    """List all sessions"""
    sessions = []
    for f in SESSIONS_DIR.glob("*.json"):
        try:
            with open(f, 'r') as file:
                data = json.load(file)
                sessions.append({
                    "session_id": f.stem,
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "completeness_score": data.get("completeness_score", 0),
                    "ready_for_threat_model": data.get("ready_for_threat_model", False),
                    "turns": len(data.get("conversation_history", []))
                })
        except:
            pass
    return sorted(sessions, key=lambda s: s.get("updated_at", ""), reverse=True)


# ===========================================
# Query Classification & Web Search
# ===========================================

def is_factual_query(message: str) -> bool:
    """Determine if a query is factual/definitional (benefits from web search)"""
    message_lower = message.lower().strip()
    
    # Patterns that indicate definition/factual questions
    factual_patterns = [
        r'^what is\s+',
        r'^what are\s+',
        r'^explain\s+',
        r'^define\s+',
        r'^how does\s+.*work',
        r'^describe\s+',
        r'^tell me about\s+',
        r'difference between\s+',
        r'\bvs\.?\s+',
        r'compare\s+',
        r'^is\s+.*\s+(part of|related to|same as)',
    ]
    
    for pattern in factual_patterns:
        if re.search(pattern, message_lower):
            return True
    
    # Check for security framework mentions
    frameworks = ['stride', 'pasta', 'dread', 'owasp', 'nist', 'mitre', 'att&ck', 'cvss', 'cwe']
    if any(fw in message_lower for fw in frameworks):
        # If asking about frameworks without system context, it's likely factual
        system_words = ['my', 'our', 'system', 'application', 'project', 'api', 'app']
        if not any(sw in message_lower for sw in system_words):
            return True
    
    return False


async def perform_web_search(query: str) -> tuple[List[SearchResult], str]:
    """Perform web search and format results for LLM context"""
    search_service = get_web_search_service()
    
    if not search_service.is_available:
        return [], ""
    
    results = await search_service.search(query, max_results=5)
    
    if not results:
        return [], ""
    
    # Format for LLM context
    context = "\n\n## Web Search Results:\n"
    for i, result in enumerate(results, 1):
        context += f"\n### Source {i}: {result.title}\n"
        context += f"URL: {result.url}\n"
        context += f"Content: {result.snippet}\n"
    
    return results, context


def format_sources_section(results: List[SearchResult]) -> str:
    """Format sources as markdown section"""
    if not results:
        return ""
    
    section = "\n\n**Sources:**\n"
    for result in results[:5]:
        section += f"- [{result.title}]({result.url})\n"
    return section


# ===========================================
# Grounding Check
# ===========================================

def check_grounding(response_text: str, web_search_enabled: bool, search_results: List[SearchResult]) -> tuple[bool, List[str]]:
    """
    Verify response adheres to grounding rules.
    Returns (is_grounded, list_of_issues)
    """
    issues = []
    
    if web_search_enabled:
        # Check for citations when making factual claims
        factual_indicators = ['is defined as', 'according to', 'was developed', 'consists of', 'includes']
        has_factual_claims = any(ind in response_text.lower() for ind in factual_indicators)
        
        # Check for source links
        has_citations = bool(re.search(r'\[.*?\]\(https?://.*?\)', response_text))
        
        if has_factual_claims and not has_citations and search_results:
            issues.append("Response contains factual claims but no citations")
    else:
        # Local mode - check for fake web claims
        web_claim_patterns = [
            r'according to.*website',
            r'I found online',
            r'I searched',
            r'I verified',
            r'I checked online',
            r'\[.*?\]\(https?://.*?\)',  # Shouldn't have citation links in local mode
        ]
        
        for pattern in web_claim_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                issues.append(f"Local mode response contains web verification claim: {pattern}")
    
    # Check for hallucination patterns (common mistakes)
    hallucination_patterns = [
        (r'STRIDE is.*(part of|component of|included in).*PASTA', "Incorrect: STRIDE is not part of PASTA"),
        (r'PASTA is.*(part of|component of|included in).*STRIDE', "Incorrect: PASTA is not part of STRIDE"),
    ]
    
    for pattern, issue in hallucination_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            issues.append(issue)
    
    return len(issues) == 0, issues


# ===========================================
# LLM Interaction
# ===========================================

async def analyze_with_llm(
    conversation_history: List[Dict], 
    user_message: str,
    web_search_enabled: bool = False,
    reasoning_level: str = "balanced"
) -> Dict:
    """Use LLM to analyze the conversation with grounded response policy and reasoning control"""
    try:
        # Get runtime config for LLM
        from app.api.settings import get_runtime_config
        runtime_config = get_runtime_config() or {}
        provider_name = runtime_config.get('provider', 'mock') if runtime_config else 'mock'
        
        # Try to get LLM provider, fallback to mock on failure
        try:
            llm = get_llm_provider(runtime_config)
            # Test connection for non-mock providers
            if provider_name != 'mock':
                try:
                    # Quick test to see if provider is reachable
                    if hasattr(llm, 'list_models'):
                        await asyncio.wait_for(llm.list_models(), timeout=5.0)
                except (asyncio.TimeoutError, Exception) as test_error:
                    logger.warning("llm_provider_unreachable", 
                                 provider=provider_name, 
                                 error=str(test_error),
                                 falling_back_to_mock=True)
                    llm = get_llm_provider({"provider": "mock"})
                    provider_name = "mock"
        except Exception as init_error:
            logger.warning("llm_provider_init_failed",
                         provider=provider_name,
                         error=str(init_error),
                         falling_back_to_mock=True)
            llm = get_llm_provider({"provider": "mock"})
            provider_name = "mock"
        
        # Get reasoning policy (use actual provider name, not the fallback)
        reasoning_service = get_reasoning_service()
        try:
            level = ReasoningLevel(reasoning_level.lower())
        except ValueError:
            level = ReasoningLevel.BALANCED
        policy = reasoning_service.get_policy(provider_name, level)
        
        search_results = []
        search_context = ""
        web_search_actually_used = False
        
        # Determine if we should search
        should_search = web_search_enabled and is_factual_query(user_message)
        
        if should_search:
            search_service = get_web_search_service()
            
            if search_service.is_available:
                search_results, search_context = await perform_web_search(user_message)
                web_search_actually_used = bool(search_results)
                logger.info("web_search_performed", 
                           query=user_message[:50], 
                           results_count=len(search_results))
            else:
                # Search requested but not available
                logger.warning("web_search_unavailable", 
                              provider=search_service.provider_name)
        
        # Build system prompt based on mode
        if web_search_actually_used:
            system_prompt = SECURITY_ARCHITECT_SYSTEM + WEB_GROUNDED_SUFFIX + search_context
        else:
            system_prompt = SECURITY_ARCHITECT_SYSTEM + LOCAL_MODE_SUFFIX
        
        # Build conversation context
        messages = [{"role": "system", "content": system_prompt}]
        
        for msg in conversation_history:
            messages.append(msg)
        
        messages.append({"role": "user", "content": user_message})
        
        # Get LLM response with reasoning policy settings
        # Wrap in try-except to handle connection errors gracefully
        try:
            response = await llm.chat(
                messages, 
                temp=policy.temperature, 
                max_tokens=policy.max_tokens
            )
        except Exception as llm_error:
            # If LLM call fails and we're not already using mock, fallback to mock
            if provider_name != 'mock':
                logger.warning("llm_chat_failed",
                             provider=provider_name,
                             error=str(llm_error),
                             falling_back_to_mock=True)
                mock_llm = get_llm_provider({"provider": "mock"})
                response = await mock_llm.chat(
                    messages,
                    temp=policy.temperature,
                    max_tokens=policy.max_tokens
                )
                # Add a note that we fell back to mock
                if isinstance(response, str):
                    response = f"[Note: Original LLM provider ({provider_name}) unavailable, using mock responses]\n\n{response}"
            else:
                # Re-raise if mock also fails (shouldn't happen)
                raise
        
        # Extract thinking block (chain-of-thought) from response
        thinking_content = None
        response_for_json = response
        
        thinking_match = re.search(r'<thinking>(.*?)</thinking>', response, re.DOTALL | re.IGNORECASE)
        if thinking_match:
            thinking_content = thinking_match.group(1).strip()
            # Remove thinking block from response for JSON parsing
            response_for_json = re.sub(r'<thinking>.*?</thinking>', '', response, flags=re.DOTALL | re.IGNORECASE).strip()
            logger.info("chain_of_thought_extracted", thinking_length=len(thinking_content))
        
        # Parse JSON response
        result = None
        try:
            json_start = response_for_json.find('{')
            json_end = response_for_json.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response_for_json[json_start:json_end]
                result = json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback if JSON parsing fails
        if not result:
            result = {
                "response_type": "general",
                "analysis": response_for_json,
                "completeness_score": 0.3,
                "missing_info": ["Could not parse LLM response properly"],
                "follow_up_questions": ["Can you tell me more about your system architecture?"],
                "ready_for_threat_model": False,
                "confidence_level": "medium",
                "uncertainty_notes": [],
                "world_model": {},
                "sources": []
            }
        
        # Add thinking content to result
        result["thinking"] = thinking_content
        
        # Grounding check
        analysis_text = result.get("analysis", "")
        is_grounded, grounding_issues = check_grounding(
            analysis_text, 
            web_search_enabled, 
            search_results
        )
        
        if not is_grounded:
            logger.warning("grounding_check_failed", issues=grounding_issues)
            # For now, log but don't regenerate - could add regeneration logic here
        
        # Add sources if web search was used
        if web_search_actually_used:
            result["sources"] = [
                {"title": r.title, "url": r.url, "snippet": r.snippet, "citation_id": r.citation_id}
                for r in search_results
            ]
            result["web_search_used"] = True
        else:
            result["web_search_used"] = False
            result["sources"] = []
        
        # Generate reasoning summary if enabled
        result["reasoning_level"] = level.value
        if reasoning_service.show_summary:
            source_titles = [r.title for r in search_results] if search_results else []
            summary = reasoning_service.extract_summary_from_response(
                result.get("analysis", ""),
                sources=source_titles,
                world_model=result.get("world_model", {}),
                completeness_score=result.get("completeness_score", 0.0)
            )
            result["reasoning_summary"] = summary.to_dict()
        else:
            result["reasoning_summary"] = None
        
        return result
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error("llm_analysis_failed", error=str(e), error_type=type(e).__name__)
        # Try to provide helpful error message
        error_msg = str(e)
        if "connection" in error_msg.lower() or "timeout" in error_msg.lower():
            raise HTTPException(
                503, 
                f"LLM provider unavailable: {error_msg}. Please check your LLM provider configuration in Settings or use Mock mode for testing."
            )
        else:
            raise HTTPException(
                500, 
                f"LLM analysis failed: {error_msg}. If this persists, try switching to Mock mode in Settings."
            )


async def generate_threats_with_llm(world_model: Dict) -> Dict:
    """Use LLM to generate comprehensive threat model with test cases"""
    try:
        # Get runtime config for LLM
        from app.api.settings import get_runtime_config
        runtime_config = get_runtime_config() or {}
        provider_name = runtime_config.get('provider', 'mock') if runtime_config else 'mock'
        
        # Try to get LLM provider, fallback to mock on failure
        try:
            llm = get_llm_provider(runtime_config)
            # Test connection for non-mock providers
            if provider_name != 'mock':
                try:
                    if hasattr(llm, 'list_models'):
                        await asyncio.wait_for(llm.list_models(), timeout=5.0)
                except (asyncio.TimeoutError, Exception) as test_error:
                    logger.warning("llm_provider_unreachable",
                                 provider=provider_name,
                                 error=str(test_error),
                                 falling_back_to_mock=True)
                    llm = get_llm_provider({"provider": "mock"})
                    provider_name = "mock"
        except Exception as init_error:
            logger.warning("llm_provider_init_failed",
                         provider=provider_name,
                         error=str(init_error),
                         falling_back_to_mock=True)
            llm = get_llm_provider({"provider": "mock"})
            provider_name = "mock"
        
        context = json.dumps(world_model, indent=2)
        prompt = THREAT_GENERATION_PROMPT.format(context=context)
        
        # Wrap LLM call in try-except for graceful fallback
        try:
            response = await llm.generate(prompt, temp=0.2, max_tokens=4000)
        except Exception as llm_error:
            # If LLM call fails and we're not already using mock, fallback to mock
            if provider_name != 'mock':
                logger.warning("llm_generate_failed",
                             provider=provider_name,
                             error=str(llm_error),
                             falling_back_to_mock=True)
                mock_llm = get_llm_provider({"provider": "mock"})
                response = await mock_llm.generate(prompt, temp=0.2, max_tokens=4000)
            else:
                # Re-raise if mock also fails (shouldn't happen)
                raise
        
        # Parse JSON response
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback threats if parsing fails
        return _generate_fallback_threats(world_model)
        
    except Exception as e:
        logger.error("threat_generation_failed", error=str(e))
        return _generate_fallback_threats(world_model)


def _generate_fallback_threats(world_model: Dict) -> Dict:
    """Generate basic threats as fallback"""
    return {
        "methodology": "STRIDE",
        "threats": [
            {
                "id": "THREAT-001",
                "category": "Spoofing",
                "title": "Authentication Bypass",
                "description": f"Attacker may bypass authentication in {world_model.get('system_type', 'the system')}",
                "attack_vector": "Credential stuffing, session hijacking, token theft",
                "prerequisites": ["Network access", "Knowledge of authentication endpoints"],
                "affected_component": "Authentication System",
                "severity": "high",
                "likelihood": "medium",
                "impact": "Unauthorized access to user accounts and data",
                "dread_score": {"damage": 8, "reproducibility": 6, "exploitability": 5, "affected_users": 8, "discoverability": 5},
                "mitigations": [
                    {
                        "id": "MIT-001",
                        "title": "Implement Multi-Factor Authentication",
                        "description": "Add a second factor to verify user identity beyond passwords",
                        "implementation_steps": [
                            "Choose MFA provider (Okta, Auth0, Duo, etc.)",
                            "Integrate MFA SDK into authentication flow",
                            "Add user enrollment workflow",
                            "Implement recovery options"
                        ],
                        "priority": "high",
                        "effort": "medium",
                        "test_cases": [
                            {
                                "id": "TC-001",
                                "title": "Verify MFA enrollment flow",
                                "description": "Test that users can successfully enroll in MFA",
                                "steps": ["Create new user", "Navigate to MFA settings", "Complete enrollment", "Verify second factor is required on next login"],
                                "expected_result": "User cannot log in with just password after MFA enrollment",
                                "tools": ["Selenium", "Manual testing"]
                            },
                            {
                                "id": "TC-002",
                                "title": "Test MFA bypass attempts",
                                "description": "Attempt to bypass MFA using common techniques",
                                "steps": ["Try direct API access without MFA", "Test session replay", "Attempt OTP reuse"],
                                "expected_result": "All bypass attempts should fail",
                                "tools": ["Burp Suite", "OWASP ZAP"]
                            }
                        ]
                    }
                ],
                "compliance_mappings": {"NIST_800_53": ["IA-2", "IA-5"], "OWASP_ASVS": ["V2.2.1", "V2.8.1"]}
            }
        ],
        "recommendations": [
            "Implement defense in depth strategy",
            "Regular security assessments and penetration testing",
            "Security awareness training for development team"
        ],
        "dfd_description": "Generate DFD based on identified components"
    }


def _generate_dfd(world_model: Dict) -> str:
    """Generate Mermaid DFD from world model"""
    components = world_model.get("components", [])
    system_type = world_model.get("system_type", "System")
    
    lines = ["flowchart TD"]
    lines.append("    subgraph External[External Entities]")
    lines.append("        User[\"👤 User\"]")
    lines.append("    end")
    
    lines.append(f"    subgraph System[{system_type}]")
    for i, comp in enumerate(components[:6]):
        lines.append(f"        C{i}[\"{comp}\"]")
    if not components:
        lines.append("        App[\"Application\"]")
    lines.append("    end")
    
    lines.append("    subgraph Data[Data Stores]")
    lines.append("        DB[(\"Database\")]")
    lines.append("    end")
    
    lines.append("")
    if components:
        lines.append("    User --> C0")
        for i in range(min(len(components) - 1, 5)):
            lines.append(f"    C{i} --> C{i+1}")
        lines.append(f"    C{min(len(components)-1, 5)} --> DB")
    else:
        lines.append("    User --> App --> DB")
    
    return "\n".join(lines)


# ===========================================
# API Endpoints
# ===========================================

@router.post("/chat", response_model=ChatResponse)
async def chat(message: ChatMessage):
    """
    Send a message to the Security Architect AI.
    The AI will analyze your input and ask follow-up questions until it has enough context.
    
    Args:
        message.web_search_enabled: When true, enables web search for grounded responses
        message.reasoning_level: Thinking depth - fast, balanced, or deep
    """
    # Get or create session
    session_id = message.session_id or str(uuid.uuid4())
    session = await load_session(session_id)
    
    if not session:
        session = {
            "session_id": session_id,
            "created_at": datetime.utcnow().isoformat(),
            "conversation_history": [],
            "world_model": {},
            "completeness_score": 0.0,
            "ready_for_threat_model": False
        }
    
    # Check web search availability if enabled
    web_search_enabled = message.web_search_enabled
    search_service = get_web_search_service()
    
    if web_search_enabled and not search_service.is_available:
        logger.warning("web_search_requested_but_unavailable",
                      provider=search_service.provider_name)
    
    # Analyze with LLM (with optional web search and reasoning level)
    llm_response = await analyze_with_llm(
        session["conversation_history"],
        message.message,
        web_search_enabled=web_search_enabled,
        reasoning_level=message.reasoning_level
    )
    
    # Update session
    session["conversation_history"].append({"role": "user", "content": message.message})
    session["conversation_history"].append({"role": "assistant", "content": json.dumps(llm_response)})
    session["world_model"] = {**session.get("world_model", {}), **llm_response.get("world_model", {})}
    session["completeness_score"] = llm_response.get("completeness_score", 0)
    session["ready_for_threat_model"] = llm_response.get("ready_for_threat_model", False)
    session["updated_at"] = datetime.utcnow().isoformat()
    
    await save_session(session_id, session)
    
    # Build human-readable response
    response_text = llm_response.get("analysis", "")
    
    # Add uncertainty notes for local mode
    uncertainty_notes = llm_response.get("uncertainty_notes", [])
    if uncertainty_notes and not llm_response.get("web_search_used"):
        response_text += "\n\n*Note: " + "; ".join(uncertainty_notes) + "*"
    
    # Add follow-up questions only for threat modeling (not definitions)
    response_type = llm_response.get("response_type", "general")
    if response_type != "definition" and llm_response.get("follow_up_questions"):
        response_text += "\n\n**Questions:**\n"
        for q in llm_response["follow_up_questions"]:
            response_text += f"• {q}\n"
    
    if llm_response.get("ready_for_threat_model"):
        response_text += "\n\n✅ **I have enough information to generate a threat model.** Click 'Generate Threat Model' when ready."
    
    # Add sources if web search was used
    sources = llm_response.get("sources", [])
    if sources:
        response_text += "\n\n**Sources:**\n"
        for source in sources[:5]:
            response_text += f"- [{source.get('title', 'Source')}]({source.get('url', '')})\n"
    
    return ChatResponse(
        session_id=session_id,
        response=response_text,
        analysis=llm_response.get("analysis"),
        completeness_score=llm_response.get("completeness_score", 0),
        missing_info=llm_response.get("missing_info", []),
        follow_up_questions=llm_response.get("follow_up_questions", []) if response_type != "definition" else [],
        ready_for_threat_model=llm_response.get("ready_for_threat_model", False),
        world_model=session["world_model"],
        conversation_history=session["conversation_history"],
        web_search_used=llm_response.get("web_search_used", False),
        sources=sources,
        confidence_level=llm_response.get("confidence_level", "high"),
        reasoning_summary=llm_response.get("reasoning_summary"),
        reasoning_level=llm_response.get("reasoning_level", "balanced"),
        thinking=llm_response.get("thinking")
    )


@router.post("/generate", response_model=ThreatModelResponse)
async def generate_threat_model(request: GenerateRequest):
    """
    Generate a comprehensive threat model from the conversation context.
    Only call this when ready_for_threat_model is True.
    """
    session = await load_session(request.session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    
    if session.get("completeness_score", 0) < 0.5:
        raise HTTPException(400, 
            f"Insufficient context (completeness: {session.get('completeness_score', 0):.0%}). "
            "Please provide more information about your system."
        )
    
    world_model = session.get("world_model", {})
    
    # Generate threats with LLM
    threat_data = await generate_threats_with_llm(world_model)
    
    # Generate DFD
    dfd_mermaid = _generate_dfd(world_model)
    
    # Create project and analysis
    project_id = str(uuid.uuid4())
    analysis_id = str(uuid.uuid4())
    
    project_data = {
        "id": project_id,
        "name": f"Security Review - {world_model.get('system_type', 'System')}",
        "description": json.dumps(world_model),
        "created_at": datetime.utcnow().isoformat(),
        "source": "ai_architect_chat"
    }
    await project_repo.save(project_id, project_data)
    
    threats = threat_data.get("threats", [])
    
    analysis_data = {
        "id": analysis_id,
        "project_id": project_id,
        "methodology": threat_data.get("methodology", "STRIDE"),
        "status": "completed",
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": datetime.utcnow().isoformat(),
        "threats": threats,
        "summary": {
            "total_threats": len(threats),
            "critical": len([t for t in threats if t.get("severity") == "critical"]),
            "high": len([t for t in threats if t.get("severity") == "high"]),
            "medium": len([t for t in threats if t.get("severity") == "medium"]),
            "low": len([t for t in threats if t.get("severity") == "low"]),
            "recommendations": threat_data.get("recommendations", [])
        },
        "dfd_mermaid": dfd_mermaid,
        "compliance_summary": {},
        "source_data": {
            "session_id": request.session_id,
            "world_model": world_model,
            "conversation_history": session.get("conversation_history", [])
        }
    }
    await analysis_repo.save(analysis_id, analysis_data)
    
    # Update session with results
    session["analysis_id"] = analysis_id
    session["project_id"] = project_id
    session["threat_model_generated"] = True
    await save_session(request.session_id, session)
    
    logger.info("threat_model_generated", 
                session_id=request.session_id,
                analysis_id=analysis_id,
                threats_count=len(threats))
    
    return ThreatModelResponse(
        success=True,
        analysis_id=analysis_id,
        project_id=project_id,
        threats_count=len(threats),
        threats=threats,
        summary=analysis_data["summary"],
        dfd_mermaid=dfd_mermaid,
        recommendations=threat_data.get("recommendations", [])
    )


@router.get("/sessions")
async def get_sessions():
    """List all chat sessions"""
    sessions = await list_sessions()
    return {"sessions": sessions}


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get a specific session"""
    session = await load_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session


@router.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a session"""
    session_file = SESSIONS_DIR / f"{session_id}.json"
    if session_file.exists():
        session_file.unlink()
    return {"status": "deleted"}


@router.get("/web-search/status")
async def get_web_search_status():
    """
    Get web search service status.
    Returns whether web search is available and which provider is configured.
    """
    search_service = get_web_search_service()
    status = search_service.get_status()
    
    # Add helpful message
    if status["available"]:
        message = f"Web search is ready ({status['provider']})"
    elif status["provider"] == "none":
        message = "Web search not configured. Set SEARCH_PROVIDER in .env (recommended: searxng)"
    else:
        message = f"Provider '{status['provider']}' is not properly configured"
    
    return {
        **status,
        "message": message
    }


@router.get("/web-search/providers")
async def get_search_providers():
    """
    Get list of available search providers with their configuration requirements.
    """
    search_service = get_web_search_service()
    return {
        "providers": search_service.get_available_providers(),
        "current": search_service.provider_name,
        "configured": search_service.is_available
    }


@router.get("/reasoning/status")
async def get_reasoning_status():
    """
    Get current reasoning/thinking time settings.
    """
    reasoning_service = get_reasoning_service()
    return {
        "default_level": reasoning_service.default_level.value,
        "show_summary": reasoning_service.show_summary,
        "levels": [
            {"id": "fast", "name": "Fast", "description": "Quick responses, minimal reasoning"},
            {"id": "balanced", "name": "Balanced", "description": "Default mode, moderate depth"},
            {"id": "deep", "name": "Deep", "description": "Extensive reasoning, may be slower"}
        ]
    }


@router.get("/web-search/test")
async def test_web_search():
    """
    Test web search connectivity by performing a sample search.
    Returns success status and sample results if available.
    """
    search_service = get_web_search_service()
    
    if not search_service.is_available:
        provider = search_service.provider_name
        if provider == "none":
            return {
                "success": False,
                "message": "Web search not configured. Set SEARCH_PROVIDER in .env (recommended: searxng)",
                "provider": provider,
                "setup_instructions": [
                    "1. Start SearXNG: docker compose -f infra/docker/compose/docker-compose.search.yml up -d",
                    "2. Add to .env: SEARCH_PROVIDER=searxng",
                    "3. Restart the backend"
                ]
            }
        return {
            "success": False,
            "message": f"Provider '{provider}' is not properly configured",
            "provider": provider
        }
    
    try:
        # Perform a test search
        results = await search_service.search("OWASP Top 10 security", max_results=3)
        
        if results:
            return {
                "success": True,
                "message": f"Web search is working! Found {len(results)} results.",
                "provider": search_service.provider_name,
                "results": [
                    {"title": r.title, "url": r.url, "snippet": r.snippet[:100] + "..."}
                    for r in results[:3]
                ]
            }
        else:
            return {
                "success": False,
                "message": "Search returned no results. The provider may be misconfigured.",
                "provider": search_service.provider_name
            }
    except Exception as e:
        logger.error("web_search_test_failed", error=str(e))
        return {
            "success": False,
            "message": f"Search test failed: {str(e)}",
            "provider": search_service.provider_name
        }

