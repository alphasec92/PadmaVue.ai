"""
Security Architect Agent
An advanced conversational agent that acts as a proactive security consultant.

Features:
- Chain-of-Thought (CoT) reasoning using LLM
- "Guess & Confirm" strategy for efficient information gathering
- Live World Model updates as conversation progresses
- Fuzzy state persistence for session recovery
- Unstructured intake (code snippets, configs, free text)
"""

import json
import re
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

import structlog

from app.services.llm_provider import get_llm_provider
from app.api.settings import get_runtime_config

logger = structlog.get_logger()


# ===========================================
# World Model Schema
# ===========================================

class ArchitectureType(str, Enum):
    WEB_APP = "web_application"
    API = "api_service"
    STATIC_SITE = "static_website"
    MOBILE_BACKEND = "mobile_backend"
    MICROSERVICES = "microservices"
    SERVERLESS = "serverless"
    DATA_PIPELINE = "data_pipeline"
    INTEGRATION = "integration"
    IOT = "iot_platform"
    UNKNOWN = "unknown"


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"
    PCI = "pci"


@dataclass
class Component:
    """A component in the architecture"""
    id: str
    name: str
    type: str
    technology: Optional[str] = None
    provider: Optional[str] = None
    exposure: str = "internal"
    data_sensitivity: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    auth_required: bool = True
    confidence: float = 1.0


@dataclass
class DataFlow:
    """A data flow between components"""
    id: str
    source: str
    target: str
    protocol: str = "HTTPS"
    data_types: List[str] = field(default_factory=list)
    encrypted: bool = True
    authenticated: bool = True
    confidence: float = 1.0


@dataclass
class TrustBoundary:
    """A trust boundary in the architecture"""
    id: str
    name: str
    components: List[str] = field(default_factory=list)
    security_level: str = "standard"


@dataclass
class WorldModel:
    """The complete world model of the architecture"""
    id: str
    created_at: str
    updated_at: str
    
    project_name: Optional[str] = None
    description: Optional[str] = None
    architecture_type: str = ArchitectureType.UNKNOWN.value
    
    tech_stack: Dict[str, Any] = field(default_factory=lambda: {
        "frontend": {"framework": None, "hosting": None, "confirmed": False},
        "backend": {"language": None, "framework": None, "hosting": None, "confirmed": False},
        "database": {"type": None, "provider": None, "confirmed": False},
        "auth": {"provider": None, "method": None, "confirmed": False},
        "storage": {"provider": None, "type": None, "confirmed": False},
        "cdn": {"provider": None, "confirmed": False},
        "waf": {"provider": None, "confirmed": False},
    })
    
    components: List[Dict] = field(default_factory=list)
    data_flows: List[Dict] = field(default_factory=list)
    trust_boundaries: List[Dict] = field(default_factory=list)
    
    data_sensitivity: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    
    topics_covered: List[str] = field(default_factory=list)
    topics_pending: List[str] = field(default_factory=list)
    assumptions: List[Dict] = field(default_factory=list)
    
    conversation_turns: int = 0
    last_topic: Optional[str] = None
    completion_score: float = 0.0


# ===========================================
# Topic Configuration
# ===========================================

TOPIC_TREE = {
    "architecture_overview": {
        "priority": 1,
        "questions": [
            "What type of application or system are you building? (e.g., web app, API, integration, microservices)",
            "Can you describe the high-level architecture and its main components?",
        ],
        "inferences": {
            "integration": ["type:integration"],
            "salesforce": ["component:salesforce", "crm:salesforce"],
            "servicenow": ["component:servicenow", "itsm:servicenow"],
            "next.js": ["frontend:react", "ssr:true"],
            "vercel": ["hosting:vercel", "cdn:vercel-edge"],
            "s3": ["storage:s3", "static:possible"],
            "lambda": ["serverless:true", "backend:aws-lambda"],
            "express": ["backend:nodejs", "framework:express"],
            "fastapi": ["backend:python", "framework:fastapi"],
            "api": ["type:api_service"],
            "microservices": ["type:microservices"],
        },
    },
    "data_flows": {
        "priority": 2,
        "questions": [
            "What data flows between the systems? What information is being transferred?",
            "How does data move through your architecture?",
        ],
        "inferences": {
            "customer": ["data:customer_data"],
            "user": ["data:user_data"],
            "order": ["data:order_data"],
            "ticket": ["data:ticket_data"],
            "sync": ["pattern:data_sync"],
            "webhook": ["pattern:webhook"],
            "batch": ["pattern:batch_processing"],
        },
    },
    "authentication": {
        "priority": 3,
        "questions": [
            "How do users or systems authenticate? What credentials or tokens are used?",
            "What identity provider or authentication method do you use?",
        ],
        "inferences": {
            "oauth": ["auth:oauth"],
            "api key": ["auth:api_key"],
            "jwt": ["auth:jwt"],
            "saml": ["auth:saml", "enterprise:true"],
            "auth0": ["auth:auth0"],
            "cognito": ["auth:cognito"],
            "service account": ["auth:service_account"],
        },
    },
    "authorization": {
        "priority": 4,
        "questions": [
            "How is authorization handled? What permissions or roles control access?",
            "Who can access what data or perform what actions?",
        ],
        "inferences": {
            "rbac": ["authz:rbac"],
            "admin": ["roles:admin,user"],
            "permission": ["authz:permission_based"],
        },
    },
    "data_sensitivity": {
        "priority": 5,
        "questions": [
            "What types of sensitive data does your system handle? (PII, financial, health, etc.)",
            "Are there compliance requirements like GDPR, HIPAA, SOC2, or PCI-DSS?",
        ],
        "inferences": {
            "pii": ["data:pii", "compliance:gdpr"],
            "phi": ["data:phi", "compliance:hipaa"],
            "pci": ["data:pci", "compliance:pci_dss"],
            "credit card": ["data:pci", "compliance:pci_dss"],
            "health": ["data:phi", "compliance:hipaa"],
            "personal": ["data:pii"],
            "financial": ["data:financial"],
        },
    },
    "network_security": {
        "priority": 6,
        "questions": [
            "What network security controls are in place? (firewalls, VPNs, WAF, etc.)",
            "How are connections between systems secured?",
        ],
        "inferences": {
            "vpc": ["network:vpc"],
            "firewall": ["security:firewall"],
            "waf": ["security:waf"],
            "https": ["encryption:tls"],
            "tls": ["encryption:tls"],
            "vpn": ["network:vpn"],
        },
    },
    "secrets_management": {
        "priority": 7,
        "questions": [
            "How are secrets, API keys, and credentials managed and stored?",
        ],
        "inferences": {
            "vault": ["secrets:hashicorp_vault"],
            "secrets manager": ["secrets:aws_secrets_manager"],
            "env": ["secrets:env_vars"],
            "key management": ["secrets:kms"],
        },
    },
    "logging_monitoring": {
        "priority": 8,
        "questions": [
            "What logging and monitoring is in place? How do you detect security issues?",
        ],
        "inferences": {
            "cloudwatch": ["logging:cloudwatch"],
            "datadog": ["monitoring:datadog"],
            "splunk": ["logging:splunk"],
            "siem": ["security:siem"],
        },
    },
}


# ===========================================
# LLM-Powered Reasoning Engine
# ===========================================

class ReasoningEngine:
    """Chain-of-Thought reasoning using LLM"""
    
    def __init__(self):
        self._llm = None
    
    def _get_llm(self):
        """Get LLM provider lazily"""
        if self._llm is None:
            config = get_runtime_config()
            self._llm = get_llm_provider(config)
        return self._llm
    
    async def analyze_input(self, user_input: str, world_model: WorldModel, history: List[Dict]) -> Dict[str, Any]:
        """Analyze user input using LLM with CoT reasoning"""
        
        context = self._build_context(world_model, history)
        
        prompt = f"""You are a Security Architect AI conducting a threat modeling interview.
Your job is to understand the user's system architecture and ask relevant follow-up questions.

CONVERSATION CONTEXT:
{json.dumps(context, indent=2)}

USER'S LATEST MESSAGE:
"{user_input}"

INSTRUCTIONS:
1. Extract any architecture information from the user's message
2. Identify what type of system they're describing
3. Determine what security-relevant information you still need
4. Generate a helpful, contextual response

Respond with a JSON object:
{{
    "understanding": "Brief summary of what you understood from their message",
    "architecture_type": "integration|web_app|api|microservices|unknown",
    "extracted_info": {{
        "components": ["list of systems/components mentioned"],
        "technologies": ["list of technologies mentioned"],
        "data_types": ["types of data mentioned"],
        "security_controls": ["any security measures mentioned"]
    }},
    "inferences": [
        {{"fact": "what you can infer", "confidence": 0.8}}
    ],
    "topics_to_mark_covered": ["list of topics from: architecture_overview, data_flows, authentication, authorization, data_sensitivity, network_security, secrets_management, logging_monitoring"],
    "next_question": {{
        "topic": "the topic this question addresses",
        "question": "Your specific, contextual follow-up question based on what they told you",
        "why": "Brief reason why you're asking this"
    }},
    "response_text": "Your full conversational response to the user. Acknowledge what they said, then ask your follow-up question. Be friendly and professional."
}}

IMPORTANT: 
- Ask questions SPECIFIC to what they described (e.g., for Salesforce-ServiceNow integration, ask about the authentication method between those specific systems)
- Don't ask generic questions - tailor them to their specific architecture
- If they described an integration, ask about the data flow, auth method, and error handling for that specific integration
- Progress through topics logically based on what's most important for their architecture type"""

        try:
            llm = self._get_llm()
            response = await llm.generate(prompt, max_tokens=1500)
            
            # Parse JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                result = json.loads(json_match.group())
                logger.info("LLM analysis successful", 
                           understanding=result.get("understanding", "")[:100])
                return result
        except Exception as e:
            logger.error("LLM analysis failed, using fallback", error=str(e))
        
        # Fallback to rule-based analysis
        return self._rule_based_analysis(user_input, world_model)
    
    def _build_context(self, model: WorldModel, history: List[Dict]) -> Dict:
        """Build context for LLM"""
        # Get last 5 conversation turns
        recent_history = []
        for msg in history[-10:]:
            recent_history.append({
                "role": msg["role"],
                "content": msg["content"][:500]  # Truncate long messages
            })
        
        return {
            "project": model.project_name,
            "architecture_type": model.architecture_type,
            "known_components": [c.get("name") for c in model.components[:10]],
            "topics_already_covered": model.topics_covered,
            "topics_still_pending": model.topics_pending,
            "completion_percentage": f"{model.completion_score:.0%}",
            "conversation_so_far": recent_history,
        }
    
    def _rule_based_analysis(self, text: str, model: WorldModel) -> Dict:
        """Fallback rule-based analysis when LLM is unavailable"""
        text_lower = text.lower()
        extracted = {"components": [], "technologies": [], "data_types": [], "security_controls": []}
        inferences = []
        topics_covered = []
        
        # Detect architecture type
        arch_type = "unknown"
        if "integration" in text_lower:
            arch_type = "integration"
            topics_covered.append("architecture_overview")
        elif "api" in text_lower:
            arch_type = "api"
            topics_covered.append("architecture_overview")
        elif "web" in text_lower or "app" in text_lower:
            arch_type = "web_app"
            topics_covered.append("architecture_overview")
        
        # Extract technologies and components
        tech_keywords = {
            "salesforce": "CRM",
            "servicenow": "ITSM",
            "aws": "Cloud",
            "azure": "Cloud",
            "postgres": "Database",
            "mysql": "Database",
            "mongodb": "Database",
            "redis": "Cache",
            "kafka": "Messaging",
            "rabbitmq": "Messaging",
        }
        
        for keyword, comp_type in tech_keywords.items():
            if keyword in text_lower:
                extracted["components"].append(f"{keyword.title()} ({comp_type})")
                extracted["technologies"].append(keyword)
                inferences.append({"fact": f"Uses {keyword}", "confidence": 0.9})
        
        # Check for data flow mentions
        if any(word in text_lower for word in ["sync", "transfer", "send", "receive", "data"]):
            topics_covered.append("data_flows")
        
        # Check for auth mentions
        if any(word in text_lower for word in ["oauth", "api key", "token", "auth", "login"]):
            topics_covered.append("authentication")
        
        # Determine next question based on what's covered
        pending = [t for t in TOPIC_TREE.keys() 
                   if t not in model.topics_covered and t not in topics_covered]
        pending.sort(key=lambda t: TOPIC_TREE[t]["priority"])
        
        # Generate contextual response
        response_parts = []
        
        if extracted["components"]:
            response_parts.append(f"I understand you're working with {', '.join(extracted['components'])}.")
        elif arch_type != "unknown":
            response_parts.append(f"Got it, you're building a {arch_type.replace('_', ' ')}.")
        else:
            response_parts.append("Thanks for that information.")
        
        # Generate contextual next question
        next_q = None
        if pending:
            next_topic = pending[0]
            
            # Generate contextual question based on what we know
            if next_topic == "data_flows" and extracted["components"]:
                question = f"What data flows between {' and '.join(extracted['components'][:2])}? What information is being synchronized or transferred?"
            elif next_topic == "authentication" and arch_type == "integration":
                question = "How do these systems authenticate with each other? (OAuth, API keys, service accounts, etc.)"
            elif next_topic == "data_sensitivity":
                question = "What types of sensitive data does this system handle? (customer PII, financial data, credentials, etc.)"
            else:
                question = TOPIC_TREE[next_topic]["questions"][0]
            
            next_q = {
                "topic": next_topic,
                "question": question,
                "why": f"Need to understand {next_topic.replace('_', ' ')}"
            }
            
            response_parts.append(f"\n\n{question}")
        
        return {
            "understanding": f"User described: {text[:100]}",
            "architecture_type": arch_type,
            "extracted_info": extracted,
            "inferences": inferences,
            "topics_to_mark_covered": topics_covered,
            "next_question": next_q,
            "response_text": " ".join(response_parts)
        }


# ===========================================
# Security Architect Agent
# ===========================================

class SecurityArchitectAgent:
    """Main Security Architect conversational agent"""
    
    def __init__(self, session_id: str = None):
        self.session_id = session_id or str(uuid.uuid4())
        self.reasoning = ReasoningEngine()
        self.world_model = self._init_world_model()
        self.conversation_history: List[Dict] = []
    
    def _init_world_model(self) -> WorldModel:
        """Initialize a new world model"""
        now = datetime.utcnow().isoformat()
        return WorldModel(
            id=self.session_id,
            created_at=now,
            updated_at=now,
            topics_pending=list(TOPIC_TREE.keys()),
        )
    
    async def process_message(self, user_message: str) -> Dict[str, Any]:
        """Process a user message and return agent response"""
        self.world_model.conversation_turns += 1
        self.world_model.updated_at = datetime.utcnow().isoformat()
        
        # Store user message
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Run LLM-powered analysis
        analysis = await self.reasoning.analyze_input(
            user_message, 
            self.world_model, 
            self.conversation_history
        )
        
        # Update world model
        updates = self._update_world_model(analysis)
        
        # Get response text
        response_text = analysis.get("response_text", "")
        if not response_text and analysis.get("next_question"):
            response_text = analysis["next_question"].get("question", "Tell me more about your system.")
        
        # Store agent response
        self.conversation_history.append({
            "role": "assistant",
            "content": response_text,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Calculate completion
        self._calculate_completion()
        
        return {
            "response": response_text,
            "response_type": "question",
            "thinking": analysis.get("understanding", ""),
            "world_model_updates": updates,
            "assumptions": analysis.get("inferences", []),
            "suggested_actions": [],
            "completion_score": self.world_model.completion_score,
            "session_id": self.session_id,
            "topics_covered": self.world_model.topics_covered,
            "topics_pending": self.world_model.topics_pending,
        }
    
    def _update_world_model(self, analysis: Dict) -> Dict:
        """Update world model based on analysis"""
        updates = {}
        
        # Update architecture type
        arch_type = analysis.get("architecture_type")
        if arch_type and arch_type != "unknown":
            self.world_model.architecture_type = arch_type
            updates["architecture_type"] = arch_type
        
        # Mark topics as covered
        for topic in analysis.get("topics_to_mark_covered", []):
            if topic not in self.world_model.topics_covered:
                self.world_model.topics_covered.append(topic)
                if topic in self.world_model.topics_pending:
                    self.world_model.topics_pending.remove(topic)
                updates.setdefault("topics_covered", []).append(topic)
        
        # Track current topic
        if analysis.get("next_question", {}).get("topic"):
            self.world_model.last_topic = analysis["next_question"]["topic"]
        
        # Add extracted components
        extracted = analysis.get("extracted_info", {})
        for comp in extracted.get("components", []):
            if comp and comp not in [c.get("name") for c in self.world_model.components]:
                self.world_model.components.append({"name": comp, "type": "extracted"})
                updates.setdefault("new_components", []).append(comp)
        
        # Store inferences as assumptions
        for inference in analysis.get("inferences", []):
            self.world_model.assumptions.append(inference)
        
        return updates
    
    def _calculate_completion(self):
        """Calculate model completion score"""
        total_topics = len(TOPIC_TREE)
        covered = len(self.world_model.topics_covered)
        
        # Base score from topics (70%)
        topic_score = (covered / total_topics) * 0.7
        
        # Bonus for having components identified (20%)
        comp_score = min(len(self.world_model.components) / 3, 1.0) * 0.2
        
        # Bonus for architecture type (10%)
        arch_score = 0.1 if self.world_model.architecture_type != "unknown" else 0.0
        
        self.world_model.completion_score = topic_score + comp_score + arch_score
    
    def get_session_summary(self) -> str:
        """Generate a summary for session recovery"""
        model = self.world_model
        
        known = []
        if model.architecture_type != ArchitectureType.UNKNOWN.value:
            known.append(f"Type: {model.architecture_type}")
        
        if model.components:
            comps = ", ".join([c.get("name", "") for c in model.components[:5]])
            known.append(f"Components: {comps}")
        
        pending = model.topics_pending[:3]
        
        return f"""**Welcome back!**

**What we've established:**
{chr(10).join(f"• {k}" for k in known) if known else "• Just getting started"}

**Still need to discuss:** {', '.join(pending) if pending else 'Almost done!'}
**Progress:** {model.completion_score:.0%} complete

Ready to continue?"""
    
    def to_dict(self) -> Dict:
        """Serialize agent state for persistence"""
        return {
            "session_id": self.session_id,
            "world_model": asdict(self.world_model),
            "conversation_history": self.conversation_history,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "SecurityArchitectAgent":
        """Restore agent from persisted state"""
        agent = cls(session_id=data["session_id"])
        wm_data = data.get("world_model", {})
        agent.world_model = WorldModel(**wm_data)
        agent.conversation_history = data.get("conversation_history", [])
        return agent


# ===========================================
# Factory Function
# ===========================================

def create_security_architect(session_id: str = None) -> SecurityArchitectAgent:
    """Create a new Security Architect agent"""
    return SecurityArchitectAgent(session_id=session_id)
