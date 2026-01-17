"""
MAESTRO Engine - Agentic AI Threat Modeling

MAESTRO (Multi-Agent Environment Security Threat Risk & Opportunity) framework
for identifying security threats in AI-powered and agentic systems.

This engine handles:
1. Applicability detection - determining if MAESTRO is relevant
2. Threat generation - creating MAESTRO-specific threats when applicable
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
import re
import structlog

logger = structlog.get_logger()


# ===========================================
# MAESTRO Categories
# ===========================================

MAESTRO_CATEGORIES = {
    "AGENT01": {
        "id": "AGENT01",
        "name": "Autonomous Action Abuse",
        "description": "Threats from AI agents taking autonomous actions without proper constraints",
        "examples": [
            "Unrestricted file system access",
            "Arbitrary code execution capabilities",
            "Uncontrolled external API calls",
            "Self-modification of agent behavior"
        ],
        "mitigations": [
            "Implement action allowlists and blocklists",
            "Add human-in-the-loop for high-risk actions",
            "Use sandboxed execution environments",
            "Implement rate limiting on agent actions"
        ]
    },
    "AGENT02": {
        "id": "AGENT02", 
        "name": "Multi-Agent Coordination Attacks",
        "description": "Vulnerabilities arising from multiple AI agents interacting",
        "examples": [
            "Agent impersonation between collaborating agents",
            "Message tampering in inter-agent communication",
            "Coordination deadlocks or race conditions",
            "Emergent malicious behavior from agent interactions"
        ],
        "mitigations": [
            "Authenticate inter-agent communications",
            "Implement message integrity checks",
            "Add coordination supervisors",
            "Monitor for anomalous agent behavior patterns"
        ]
    },
    "AGENT03": {
        "id": "AGENT03",
        "name": "Tool/MCP Exploitation",
        "description": "Risks from AI agents using external tools and Model Context Protocol servers",
        "examples": [
            "Tool injection via malicious prompts",
            "Excessive permissions on tool access",
            "Data exfiltration through tool misuse",
            "MCP server compromise affecting agent behavior"
        ],
        "mitigations": [
            "Implement least-privilege tool access",
            "Validate tool inputs and outputs",
            "Audit tool usage patterns",
            "Isolate MCP server environments"
        ]
    },
    "AGENT04": {
        "id": "AGENT04",
        "name": "Memory/Context Manipulation",
        "description": "Attacks targeting AI agent memory, context windows, and retrieval systems",
        "examples": [
            "Poisoning vector database embeddings",
            "Context window overflow attacks",
            "Memory persistence exploits",
            "RAG retrieval manipulation"
        ],
        "mitigations": [
            "Validate data before embedding",
            "Implement context window guards",
            "Use content filtering on retrieved data",
            "Audit memory/context access patterns"
        ]
    },
    "AGENT05": {
        "id": "AGENT05",
        "name": "Goal/Objective Hijacking",
        "description": "Attacks that redirect AI agent goals or decision-making",
        "examples": [
            "Prompt injection altering agent objectives",
            "Reward hacking in goal-directed systems",
            "Instruction override attacks",
            "Decision boundary manipulation"
        ],
        "mitigations": [
            "Implement goal validation checks",
            "Use constitutional AI principles",
            "Add intent verification steps",
            "Monitor for objective drift"
        ]
    },
    "AGENT06": {
        "id": "AGENT06",
        "name": "LLM Decision Trust Exploitation",
        "description": "Risks from over-reliance on LLM outputs for critical decisions",
        "examples": [
            "Hallucinated data affecting downstream actions",
            "Confidence score manipulation",
            "Inconsistent decision outputs",
            "Adversarial input causing wrong decisions"
        ],
        "mitigations": [
            "Implement decision validation layers",
            "Add confidence thresholds for actions",
            "Use multiple model consensus",
            "Human review for critical decisions"
        ]
    }
}


# ===========================================
# Evidence Detection Signals
# ===========================================

AI_AGENT_SIGNALS = {
    # Keywords indicating AI/Agent components
    "keywords": [
        "langchain", "langgraph", "autogen", "crewai", "swarm",
        "agent", "multi-agent", "autonomous", "agentic",
        "llm", "gpt", "claude", "openai", "anthropic", "gemini",
        "tool_use", "function_calling", "mcp", "model context protocol",
        "vector", "embedding", "rag", "retrieval",
        "memory", "context", "conversation_history",
        "orchestrator", "workflow", "chain",
        "web_search", "search_grounding", "grounded",
        "langsmith", "langfuse", "arize"
    ],
    
    # Configuration patterns
    "config_patterns": [
        r"OPENAI_API_KEY",
        r"ANTHROPIC_API_KEY",
        r"LLM_PROVIDER",
        r"AGENT_.*",
        r"MCP_.*",
        r"VECTOR_.*",
        r"RAG_.*",
        r"EMBEDDING_.*"
    ],
    
    # Code patterns
    "code_patterns": [
        r"ChatOpenAI|ChatAnthropic|ChatVertexAI",
        r"Agent\(|AgentExecutor|create_.*_agent",
        r"ToolExecutor|tool_executor",
        r"VectorStore|Chroma|Pinecone|Qdrant|Weaviate",
        r"ConversationBufferMemory|ConversationSummaryMemory",
        r"RetrievalQA|RetrievalChain",
        r"LangGraph|StateGraph|MessageGraph"
    ],
    
    # Architecture indicators
    "architecture_indicators": [
        "microservices with ai",
        "ai-powered",
        "llm-based",
        "conversational ai",
        "chatbot",
        "virtual assistant",
        "ai agent",
        "autonomous system"
    ]
}


@dataclass
class EvidenceItem:
    """A piece of evidence for MAESTRO applicability"""
    source: str  # "document" | "chat" | "config" | "code" | "metadata"
    snippet: str
    signal_type: str
    file: Optional[str] = None
    path: Optional[str] = None
    confidence: float = 0.8


@dataclass
class MaestroApplicability:
    """Result of MAESTRO applicability check"""
    applicable: bool
    confidence: float  # 0.0 to 1.0
    reasons: List[str]
    evidence: List[Dict]  # List of EvidenceItem as dicts
    signals: Dict[str, Any] = field(default_factory=dict)
    status: str = "detected"  # "detected" | "not_detected" | "forced"
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class MAESTROEngine:
    """
    MAESTRO Engine for Agentic AI threat analysis.
    
    Handles:
    1. Applicability detection (checking if MAESTRO is relevant)
    2. Threat generation (creating MAESTRO-specific threats)
    """
    
    def __init__(self):
        self.categories = MAESTRO_CATEGORIES
        self.signals = AI_AGENT_SIGNALS
    
    def check_applicability(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Optional[Dict[str, Any]] = None,
        parsed_content: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        force: bool = False
    ) -> MaestroApplicability:
        """
        Check if MAESTRO threat modeling is applicable to this project.
        
        This is the NO-HALLUCINATION gate - only returns applicable=True
        when there is actual evidence of AI/agent components.
        
        Args:
            project_data: Project information
            elicitation_results: Results from user elicitation/architect flow
            parsed_content: Parsed document content
            metadata: Additional metadata (config, file types, etc.)
            force: If True, returns applicable=True regardless (but marks as "forced")
        
        Returns:
            MaestroApplicability with evidence-backed decision
        """
        evidence_items: List[EvidenceItem] = []
        signals_found: Dict[str, List[str]] = {
            "keywords": [],
            "config": [],
            "code": [],
            "architecture": [],
            "explicit": []
        }
        
        # If forced, still collect evidence but always return applicable
        if force:
            logger.info("MAESTRO applicability forced by user")
        
        # 1. Check project metadata
        project_name = project_data.get("name", "").lower()
        project_desc = project_data.get("description", "").lower()
        
        self._check_text_for_signals(
            f"{project_name} {project_desc}",
            evidence_items,
            signals_found,
            source="metadata"
        )
        
        # 2. Check architecture types from project
        arch_types = project_data.get("architecture_types", [])
        for arch in arch_types:
            arch_lower = arch.lower()
            for indicator in self.signals["architecture_indicators"]:
                if indicator in arch_lower:
                    evidence_items.append(EvidenceItem(
                        source="metadata",
                        snippet=f"Architecture type: {arch}",
                        signal_type="architecture",
                        confidence=0.9
                    ))
                    signals_found["architecture"].append(arch)
        
        # 3. Check elicitation results (user answers)
        if elicitation_results:
            self._check_elicitation(elicitation_results, evidence_items, signals_found)
        
        # 4. Check parsed document content
        if parsed_content:
            self._check_text_for_signals(
                parsed_content,
                evidence_items,
                signals_found,
                source="document"
            )
        
        # 5. Check metadata for config patterns
        if metadata:
            self._check_metadata(metadata, evidence_items, signals_found)
        
        # 6. Check project files list
        files = project_data.get("files", [])
        self._check_files(files, evidence_items, signals_found)
        
        # Calculate confidence and decision
        total_evidence = len(evidence_items)
        
        if force:
            return MaestroApplicability(
                applicable=True,
                confidence=0.5,  # Lower confidence for forced
                reasons=["MAESTRO forced by user (not auto-detected)"],
                evidence=[asdict(e) for e in evidence_items],
                signals=signals_found,
                status="forced"
            )
        
        if total_evidence == 0:
            return MaestroApplicability(
                applicable=False,
                confidence=1.0,  # High confidence that it's NOT applicable
                reasons=["No AI/agent components detected in project"],
                evidence=[],
                signals=signals_found,
                status="not_detected"
            )
        
        # Calculate confidence based on evidence strength
        confidence = self._calculate_confidence(evidence_items, signals_found)
        
        # Generate reasons from evidence
        reasons = self._generate_reasons(evidence_items, signals_found)
        
        return MaestroApplicability(
            applicable=confidence >= 0.3,  # Threshold for applicability
            confidence=confidence,
            reasons=reasons,
            evidence=[asdict(e) for e in evidence_items[:20]],  # Limit evidence
            signals=signals_found,
            status="detected" if confidence >= 0.3 else "not_detected"
        )
    
    def _check_text_for_signals(
        self,
        text: str,
        evidence_items: List[EvidenceItem],
        signals_found: Dict[str, List[str]],
        source: str = "document"
    ):
        """Check text content for AI/agent signals."""
        text_lower = text.lower()
        
        # Check keywords
        for keyword in self.signals["keywords"]:
            if keyword in text_lower:
                # Find context around keyword
                idx = text_lower.find(keyword)
                start = max(0, idx - 50)
                end = min(len(text), idx + len(keyword) + 50)
                snippet = text[start:end].strip()
                
                evidence_items.append(EvidenceItem(
                    source=source,
                    snippet=f"...{snippet}...",
                    signal_type="keyword",
                    confidence=0.7 if keyword in ["agent", "llm"] else 0.85
                ))
                signals_found["keywords"].append(keyword)
        
        # Check code patterns
        for pattern in self.signals["code_patterns"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:3]:  # Limit matches
                evidence_items.append(EvidenceItem(
                    source=source,
                    snippet=f"Code pattern found: {match}",
                    signal_type="code",
                    confidence=0.9
                ))
                signals_found["code"].append(match)
    
    def _check_elicitation(
        self,
        elicitation_results: Dict[str, Any],
        evidence_items: List[EvidenceItem],
        signals_found: Dict[str, List[str]]
    ):
        """Check elicitation/architect responses for AI indicators."""
        # Check explicit AI/agent mentions in answers
        answers = elicitation_results.get("answers", {})
        for key, value in answers.items():
            if isinstance(value, str):
                self._check_text_for_signals(
                    value, evidence_items, signals_found, source="chat"
                )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        self._check_text_for_signals(
                            item, evidence_items, signals_found, source="chat"
                        )
        
        # Check summary
        summary = elicitation_results.get("summary", "")
        if summary:
            self._check_text_for_signals(
                summary, evidence_items, signals_found, source="chat"
            )
        
        # Check components list
        components = elicitation_results.get("components", [])
        for comp in components:
            comp_lower = comp.lower() if isinstance(comp, str) else str(comp).lower()
            for keyword in ["ai", "llm", "agent", "ml", "model", "gpt", "embedding"]:
                if keyword in comp_lower:
                    evidence_items.append(EvidenceItem(
                        source="chat",
                        snippet=f"Component identified: {comp}",
                        signal_type="explicit",
                        confidence=0.95
                    ))
                    signals_found["explicit"].append(comp)
    
    def _check_metadata(
        self,
        metadata: Dict[str, Any],
        evidence_items: List[EvidenceItem],
        signals_found: Dict[str, List[str]]
    ):
        """Check metadata for configuration patterns."""
        metadata_str = str(metadata).lower()
        
        for pattern in self.signals["config_patterns"]:
            matches = re.findall(pattern, str(metadata), re.IGNORECASE)
            for match in matches:
                evidence_items.append(EvidenceItem(
                    source="config",
                    snippet=f"Config pattern: {match}",
                    signal_type="config",
                    confidence=0.85
                ))
                signals_found["config"].append(match)
        
        # Check for MCP servers
        if "mcp" in metadata_str or "mcp_servers" in metadata:
            evidence_items.append(EvidenceItem(
                source="config",
                snippet="MCP servers configured",
                signal_type="explicit",
                confidence=0.95
            ))
            signals_found["explicit"].append("MCP")
        
        # Check for web search / grounding
        if "web_search" in metadata_str or "search_grounding" in metadata_str:
            evidence_items.append(EvidenceItem(
                source="config",
                snippet="Web search / grounding enabled",
                signal_type="explicit",
                confidence=0.85
            ))
            signals_found["explicit"].append("web_search")
    
    def _check_files(
        self,
        files: List[Dict],
        evidence_items: List[EvidenceItem],
        signals_found: Dict[str, List[str]]
    ):
        """Check project files for AI-related indicators."""
        ai_related_files = [
            "langchain", "langgraph", "agents", "llm", "mcp",
            "embedding", "vector", "rag", "chain"
        ]
        
        for file_info in files:
            filename = file_info.get("name", "").lower()
            for indicator in ai_related_files:
                if indicator in filename:
                    evidence_items.append(EvidenceItem(
                        source="document",
                        snippet=f"AI-related file: {file_info.get('name', 'unknown')}",
                        signal_type="architecture",
                        file=file_info.get("name"),
                        confidence=0.8
                    ))
                    signals_found["architecture"].append(filename)
    
    def _calculate_confidence(
        self,
        evidence_items: List[EvidenceItem],
        signals_found: Dict[str, List[str]]
    ) -> float:
        """Calculate overall confidence score from evidence."""
        if not evidence_items:
            return 0.0
        
        # Weight different signal types
        weights = {
            "explicit": 1.0,
            "code": 0.9,
            "config": 0.85,
            "keyword": 0.7,
            "architecture": 0.8
        }
        
        total_weight = 0.0
        weighted_confidence = 0.0
        
        for evidence in evidence_items:
            weight = weights.get(evidence.signal_type, 0.5)
            total_weight += weight
            weighted_confidence += evidence.confidence * weight
        
        if total_weight == 0:
            return 0.0
        
        base_confidence = weighted_confidence / total_weight
        
        # Boost confidence for diversity of signals
        signal_types_found = sum(1 for v in signals_found.values() if v)
        diversity_boost = min(0.2, signal_types_found * 0.05)
        
        return min(1.0, base_confidence + diversity_boost)
    
    def _generate_reasons(
        self,
        evidence_items: List[EvidenceItem],
        signals_found: Dict[str, List[str]]
    ) -> List[str]:
        """Generate human-readable reasons from evidence."""
        reasons = []
        
        if signals_found["explicit"]:
            reasons.append(f"Explicit AI components: {', '.join(signals_found['explicit'][:5])}")
        
        if signals_found["code"]:
            reasons.append(f"AI/Agent code patterns detected: {', '.join(signals_found['code'][:3])}")
        
        if signals_found["config"]:
            reasons.append(f"AI-related configuration found: {', '.join(signals_found['config'][:3])}")
        
        if signals_found["keywords"]:
            unique_keywords = list(set(signals_found["keywords"]))[:5]
            reasons.append(f"AI keywords found: {', '.join(unique_keywords)}")
        
        if signals_found["architecture"]:
            reasons.append(f"AI architecture indicators: {', '.join(signals_found['architecture'][:3])}")
        
        if not reasons:
            reasons.append("General AI/agent signals detected in project data")
        
        return reasons
    
    def generate_threats(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Optional[Dict[str, Any]] = None,
        applicability: Optional[MaestroApplicability] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate MAESTRO threats based on detected AI components.
        
        Only generates threats that are relevant to the detected signals.
        """
        threats = []
        
        # Get signals from applicability or recalculate
        if applicability:
            signals = applicability.signals
            evidence = applicability.evidence
        else:
            check_result = self.check_applicability(
                project_data, elicitation_results
            )
            signals = check_result.signals
            evidence = check_result.evidence
        
        # Determine which categories are relevant
        relevant_categories = self._determine_relevant_categories(signals, evidence)
        
        project_name = project_data.get("name", "Unknown Project")
        
        for cat_id in relevant_categories:
            category = self.categories[cat_id]
            
            threat = {
                "id": f"MAESTRO-{cat_id}-{project_data.get('id', 'unknown')[:8]}",
                "methodology": "maestro",
                "category": cat_id,
                "title": f"{category['name']} Risk",
                "description": category["description"],
                "affected_component": self._get_affected_component(cat_id, signals, project_name),
                "attack_vector": category["examples"][0] if category["examples"] else "AI system exploitation",
                "severity": self._determine_severity(cat_id, signals),
                "mitigations": category["mitigations"][:4],
                "owasp_mappings": {
                    "agentic_ai": [cat_id],
                    "owasp_llm": self._map_to_llm_top10(cat_id)
                },
                "evidence": self._filter_evidence_for_category(cat_id, evidence),
                "dread_score": {
                    "damage": 7,
                    "reproducibility": 6,
                    "exploitability": 5,
                    "affected_users": 7,
                    "discoverability": 5
                },
                "overall_risk": 6.0,
                "trust_level": "high" if applicability and applicability.status == "detected" else "medium"
            }
            
            threats.append(threat)
        
        return threats
    
    def _determine_relevant_categories(
        self,
        signals: Dict[str, List[str]],
        evidence: List[Dict]
    ) -> List[str]:
        """Determine which MAESTRO categories are relevant based on signals."""
        relevant = []
        all_text = " ".join([
            " ".join(signals.get("keywords", [])),
            " ".join(signals.get("explicit", [])),
            " ".join(signals.get("code", []))
        ]).lower()
        
        # AGENT01 - Autonomous actions
        if any(kw in all_text for kw in ["tool", "function", "execute", "action", "mcp"]):
            relevant.append("AGENT01")
        
        # AGENT02 - Multi-agent
        if any(kw in all_text for kw in ["multi-agent", "crew", "swarm", "orchestrat"]):
            relevant.append("AGENT02")
        
        # AGENT03 - Tool/MCP
        if any(kw in all_text for kw in ["mcp", "tool", "function_call", "web_search"]):
            relevant.append("AGENT03")
        
        # AGENT04 - Memory/Context
        if any(kw in all_text for kw in ["memory", "rag", "retrieval", "vector", "embedding", "context"]):
            relevant.append("AGENT04")
        
        # AGENT05 - Goal hijacking (always relevant for AI systems)
        if any(kw in all_text for kw in ["agent", "llm", "gpt", "claude", "openai", "anthropic"]):
            relevant.append("AGENT05")
        
        # AGENT06 - LLM trust (always relevant when LLMs are used)
        if any(kw in all_text for kw in ["llm", "gpt", "claude", "gemini", "decision"]):
            relevant.append("AGENT06")
        
        # If we have AI signals but couldn't map to specific categories, add general ones
        if not relevant and (signals.get("keywords") or signals.get("explicit")):
            relevant = ["AGENT05", "AGENT06"]  # Always relevant for any AI system
        
        return relevant
    
    def _get_affected_component(
        self,
        category_id: str,
        signals: Dict[str, List[str]],
        project_name: str
    ) -> str:
        """Determine the affected component based on category and signals."""
        explicit = signals.get("explicit", [])
        
        if category_id == "AGENT03" and "MCP" in explicit:
            return "MCP Server Integration"
        elif category_id == "AGENT04" and any("vector" in s.lower() for s in explicit):
            return "Vector Store / RAG System"
        elif category_id == "AGENT01":
            return "Agent Action Executor"
        elif category_id == "AGENT02":
            return "Multi-Agent Orchestrator"
        else:
            return f"{project_name} AI System"
    
    def _determine_severity(
        self,
        category_id: str,
        signals: Dict[str, List[str]]
    ) -> str:
        """Determine threat severity based on category and signals."""
        # Higher severity for categories with more direct impact
        high_severity_cats = ["AGENT01", "AGENT05"]  # Autonomous actions, goal hijacking
        medium_high_cats = ["AGENT03", "AGENT06"]  # Tool abuse, LLM trust
        
        explicit_count = len(signals.get("explicit", []))
        
        if category_id in high_severity_cats:
            return "high" if explicit_count > 1 else "medium"
        elif category_id in medium_high_cats:
            return "medium"
        else:
            return "medium" if explicit_count > 0 else "low"
    
    def _map_to_llm_top10(self, category_id: str) -> List[str]:
        """Map MAESTRO categories to OWASP LLM Top 10."""
        mapping = {
            "AGENT01": ["LLM07"],  # Insecure Plugin Design
            "AGENT02": ["LLM07", "LLM09"],  # Plugin Design, Overreliance
            "AGENT03": ["LLM07", "LLM05"],  # Plugin Design, Supply Chain
            "AGENT04": ["LLM03", "LLM06"],  # Training Data, Sensitive Info
            "AGENT05": ["LLM01", "LLM02"],  # Prompt Injection, Insecure Output
            "AGENT06": ["LLM09", "LLM02"]   # Overreliance, Insecure Output
        }
        return mapping.get(category_id, [])
    
    def _filter_evidence_for_category(
        self,
        category_id: str,
        evidence: List[Dict]
    ) -> List[Dict]:
        """Filter evidence relevant to a specific category."""
        # Keywords associated with each category
        category_keywords = {
            "AGENT01": ["action", "execute", "autonomo", "tool", "function"],
            "AGENT02": ["multi", "agent", "orchestrat", "crew", "swarm"],
            "AGENT03": ["mcp", "tool", "plugin", "function_call", "search"],
            "AGENT04": ["memory", "rag", "retriev", "vector", "embedding", "context"],
            "AGENT05": ["prompt", "goal", "objective", "instruct"],
            "AGENT06": ["llm", "decision", "output", "trust", "confiden"]
        }
        
        keywords = category_keywords.get(category_id, [])
        
        filtered = []
        for ev in evidence:
            snippet = ev.get("snippet", "").lower()
            if any(kw in snippet for kw in keywords):
                filtered.append(ev)
        
        return filtered[:5]  # Limit to 5 evidence items per category

    @staticmethod
    def get_all_categories() -> Dict[str, Dict]:
        """Return all MAESTRO categories for reference."""
        return MAESTRO_CATEGORIES
