"""
Threat Agent
Supports both STRIDE and PASTA threat modeling methodologies
with OWASP framework mappings including AI/LLM Top 10 and Agentic AI security
"""

from typing import Dict, Any, List, Optional
import json
import uuid

import structlog

from app.services.llm_provider import LLMProvider
from app.engines.stride import STRIDEEngine
from app.engines.pasta import PASTAEngine
from app.engines.dread import DREADEngine
from app.engines.owasp_mapper import OWASPMapper
from app.engines.maestro import MAESTROEngine, MaestroApplicability

logger = structlog.get_logger()


class ThreatAgent:
    """
    Threat Agent for comprehensive threat modeling.
    
    Supports:
    - STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege
    - PASTA: Process for Attack Simulation and Threat Analysis (7-stage risk-centric)
    
    Both methodologies include DREAD scoring for risk quantification.
    """
    
    STRIDE_SYSTEM_PROMPT = """You are a Security Threat Modeling Agent specialized in STRIDE analysis with OWASP framework expertise.
Your role is to identify potential security threats in software systems and map them to OWASP frameworks.

STRIDE Categories:
- Spoofing: Identity threats (authentication bypass, impersonation)
- Tampering: Data integrity threats (injection, modification)
- Repudiation: Audit threats (log tampering, non-accountability)
- Information Disclosure: Confidentiality threats (data leaks, exposure)
- Denial of Service: Availability threats (resource exhaustion, crashes)
- Elevation of Privilege: Authorization threats (privilege escalation, IDOR)

OWASP Framework Mappings (include for each threat):
- OWASP Top 10 Web (A01-A10:2021)
- OWASP API Security Top 10 (API1-API10:2023) - if APIs are involved
- OWASP LLM AI Top 10 (LLM01-LLM10:2025) - if AI/ML components exist
- Agentic AI Threats (AGENT01-AGENT05) - if AI agents are used

For each threat, provide:
1. Clear title and description
2. Affected component
3. Attack vector
4. DREAD scores (1-10 scale)
5. Mitigation recommendations
6. OWASP framework mappings (owasp_top_10, owasp_api, owasp_llm, agentic_ai)

Output valid JSON with comprehensive threat analysis including OWASP mappings."""

    PASTA_SYSTEM_PROMPT = """You are a Security Threat Modeling Agent specialized in PASTA analysis.
PASTA (Process for Attack Simulation and Threat Analysis) is a 7-stage risk-centric methodology.

Focus on:
1. Business objectives and security requirements
2. Technical scope and architecture
3. Application decomposition and data flows
4. Threat agent identification and analysis
5. Vulnerability correlation
6. Attack modeling and simulation
7. Risk quantification and prioritization

For each threat, provide:
1. Threat agent profile (who would attack)
2. Attack vector and entry point
3. Affected assets and business impact
4. Likelihood and impact scores (1-5)
5. Risk level and countermeasures

Output valid JSON with comprehensive PASTA analysis."""
    
    def __init__(self, llm: LLMProvider):
        self.llm = llm
        self.stride_engine = STRIDEEngine()
        self.pasta_engine = PASTAEngine()
        self.dread_engine = DREADEngine()
        self.owasp_mapper = OWASPMapper()
        self.maestro_engine = MAESTROEngine()
    
    async def run(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any],
        severity_threshold: str = "low",
        methodology: str = "stride",  # Primary: "stride" or "pasta"
        include_maestro: bool = False,
        force_maestro: bool = False,
        maestro_confidence_threshold: float = 0.6,
        parsed_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run threat modeling analysis using selected methodology with optional MAESTRO overlay.
        
        Args:
            project_data: Project metadata
            elicitation_results: Results from elicitation agent
            severity_threshold: Minimum severity to include
            methodology: Primary methodology - "stride" or "pasta"
            include_maestro: Whether to include MAESTRO (Agentic AI) analysis
            force_maestro: Force MAESTRO even if not auto-detected
            maestro_confidence_threshold: Confidence threshold for MAESTRO applicability
            parsed_content: Optional parsed document content for evidence detection
        
        Returns:
            Threat analysis results with OWASP mappings and optional MAESTRO results
        """
        methodology = methodology.lower()
        logger.info(
            f"Running {methodology.upper()} threat modeling with OWASP mappings",
            include_maestro=include_maestro,
            force_maestro=force_maestro
        )
        
        # Detect AI/Agent components in the system
        has_ai = self._detect_ai_components(project_data, elicitation_results)
        has_agents = self._detect_agent_components(project_data, elicitation_results)
        has_api = self._detect_api_components(project_data, elicitation_results)
        
        logger.info("Component detection", has_ai=has_ai, has_agents=has_agents, has_api=has_api)
        
        # Run primary methodology (STRIDE or PASTA)
        if methodology == "pasta":
            result = await self._run_pasta_analysis(
                project_data,
                elicitation_results,
                severity_threshold,
                parsed_content=parsed_content
            )
        else:
            result = await self._run_stride_analysis(
                project_data,
                elicitation_results,
                severity_threshold,
                parsed_content=parsed_content
            )
        
        # Add OWASP compliance report
        result["owasp_compliance"] = self._generate_owasp_compliance(
            result.get("threats", []),
            has_ai,
            has_agents,
            has_api
        )
        
        # Add AI-specific threats if AI components detected
        if has_ai or has_agents:
            ai_threats = self._get_ai_specific_threats(has_ai, has_agents)
            result["ai_specific_threats"] = ai_threats
            result["ai_mitigations"] = self.owasp_mapper.get_ai_specific_mitigations(has_ai, has_agents)
        
        result["has_ai_components"] = has_ai
        result["has_agent_components"] = has_agents
        result["has_api"] = has_api
        
        # MAESTRO Analysis (Agentic AI Threats) - NO HALLUCINATION GATE
        result["maestro_applicability"] = None
        result["maestro_threats"] = []
        
        if include_maestro:
            maestro_result = await self._run_maestro_analysis(
                project_data=project_data,
                elicitation_results=elicitation_results,
                parsed_content=parsed_content,
                force=force_maestro,
                confidence_threshold=maestro_confidence_threshold
            )
            result["maestro_applicability"] = maestro_result["applicability"]
            result["maestro_threats"] = maestro_result["threats"]
            
            # If MAESTRO threats were generated, add them to the main threats list
            # with methodology="maestro" tag
            if maestro_result["threats"]:
                result["threats"].extend(maestro_result["threats"])
                logger.info(
                    f"Added {len(maestro_result['threats'])} MAESTRO threats",
                    status=maestro_result["applicability"]["status"]
                )
        
        return result
    
    async def _run_maestro_analysis(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any],
        parsed_content: Optional[str] = None,
        force: bool = False,
        confidence_threshold: float = 0.6
    ) -> Dict[str, Any]:
        """
        Run MAESTRO (Agentic AI) threat analysis.
        
        This implements the NO-HALLUCINATION requirement:
        - Only generates MAESTRO threats when there's evidence of AI/agent components
        - Evidence is stored and shown in results
        - Force flag allows override but marks results as "forced"
        """
        # Step 1: Check applicability (the evidence gate)
        applicability = self.maestro_engine.check_applicability(
            project_data=project_data,
            elicitation_results=elicitation_results,
            parsed_content=parsed_content,
            metadata=project_data.get("metadata", {}),
            force=force
        )
        
        logger.info(
            "MAESTRO applicability check complete",
            applicable=applicability.applicable,
            confidence=applicability.confidence,
            status=applicability.status,
            evidence_count=len(applicability.evidence)
        )
        
        # Step 2: Only generate threats if applicable or forced
        threats = []
        
        should_generate = (
            force or 
            (applicability.applicable and applicability.confidence >= confidence_threshold)
        )
        
        if should_generate:
            threats = self.maestro_engine.generate_threats(
                project_data=project_data,
                elicitation_results=elicitation_results,
                applicability=applicability
            )
            logger.info(f"Generated {len(threats)} MAESTRO threats")
        else:
            logger.info(
                "MAESTRO threats not generated - not applicable",
                confidence=applicability.confidence,
                threshold=confidence_threshold
            )
        
        return {
            "applicability": {
                "applicable": applicability.applicable,
                "confidence": applicability.confidence,
                "status": applicability.status,
                "reasons": applicability.reasons,
                "evidence": applicability.evidence,
                "signals": applicability.signals,
                "checked_at": applicability.checked_at
            },
            "threats": threats
        }
    
    def _detect_ai_components(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any]
    ) -> bool:
        """Detect if the system has AI/ML components"""
        ai_keywords = [
            "llm", "ai", "ml", "machine learning", "neural", "model", 
            "gpt", "chatbot", "openai", "anthropic", "gemini", "claude",
            "embedding", "vector", "rag", "retrieval", "inference",
            "nlp", "natural language", "transformer", "bert", "language model"
        ]
        
        text_to_search = json.dumps(project_data).lower() + " " + json.dumps(elicitation_results).lower()
        return any(kw in text_to_search for kw in ai_keywords)
    
    def _detect_agent_components(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any]
    ) -> bool:
        """Detect if the system has AI agent components"""
        agent_keywords = [
            "agent", "agentic", "autonomous", "tool calling", "function calling",
            "mcp", "langchain", "autogen", "crew", "swarm", "orchestration",
            "multi-agent", "workflow", "automation", "self-driving"
        ]
        
        text_to_search = json.dumps(project_data).lower() + " " + json.dumps(elicitation_results).lower()
        return any(kw in text_to_search for kw in agent_keywords)
    
    def _detect_api_components(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any]
    ) -> bool:
        """Detect if the system exposes APIs"""
        api_keywords = [
            "api", "rest", "graphql", "grpc", "endpoint", "webhook",
            "microservice", "service", "http", "json", "oauth"
        ]
        
        text_to_search = json.dumps(project_data).lower() + " " + json.dumps(elicitation_results).lower()
        return any(kw in text_to_search for kw in api_keywords)
    
    def _generate_owasp_compliance(
        self,
        threats: List[Dict[str, Any]],
        has_ai: bool,
        has_agents: bool,
        has_api: bool
    ) -> Dict[str, Any]:
        """Generate OWASP compliance report"""
        # Extract OWASP IDs from threats
        identified_owasp = set()
        for threat in threats:
            owasp_mappings = threat.get("owasp_mappings", {})
            identified_owasp.update(owasp_mappings.get("owasp_top_10", []))
            identified_owasp.update(owasp_mappings.get("owasp_api", []))
            identified_owasp.update(owasp_mappings.get("owasp_llm", []))
            identified_owasp.update(owasp_mappings.get("agentic_ai", []))
        
        return self.owasp_mapper.generate_compliance_report(
            list(identified_owasp),
            has_ai,
            has_agents
        )
    
    def _get_ai_specific_threats(
        self,
        has_ai: bool,
        has_agents: bool
    ) -> List[Dict[str, Any]]:
        """Get AI-specific threats based on detected components"""
        threats = []
        
        if has_ai:
            # Add LLM-specific threats
            llm_threats = [
                {
                    "id": "AI-THREAT-001",
                    "owasp_id": "LLM01:2025",
                    "title": "Prompt Injection Attack",
                    "category": "AI Security",
                    "severity": "critical",
                    "description": "Attackers can craft malicious inputs to manipulate LLM behavior, bypass restrictions, or extract sensitive information.",
                    "attack_vector": "Direct injection through user input or indirect injection via external content",
                    "mitigations": [
                        "Implement strict input/output filtering",
                        "Separate system prompts from user content clearly",
                        "Use defense-in-depth with multiple validation layers",
                        "Mark untrusted content distinctly"
                    ]
                },
                {
                    "id": "AI-THREAT-002",
                    "owasp_id": "LLM02:2025",
                    "title": "Sensitive Data Leakage via LLM",
                    "category": "AI Security",
                    "severity": "high",
                    "description": "LLM may inadvertently reveal training data, PII, or confidential information in its responses.",
                    "attack_vector": "Crafted prompts designed to extract memorized training data or system information",
                    "mitigations": [
                        "Filter outputs for sensitive data patterns (PII, credentials)",
                        "Apply differential privacy techniques",
                        "Limit LLM access to sensitive data stores",
                        "Implement output classification and redaction"
                    ]
                },
                {
                    "id": "AI-THREAT-003",
                    "owasp_id": "LLM09:2025",
                    "title": "Hallucination and Misinformation",
                    "category": "AI Security",
                    "severity": "medium",
                    "description": "LLM may generate false, misleading, or fabricated information that appears authoritative.",
                    "attack_vector": "Exploiting model's tendency to generate plausible-sounding but incorrect outputs",
                    "mitigations": [
                        "Implement RAG with verified knowledge sources",
                        "Add confidence scoring to outputs",
                        "Require human review for critical decisions",
                        "Implement fact-checking pipelines"
                    ]
                }
            ]
            threats.extend(llm_threats)
        
        if has_agents:
            # Add agent-specific threats
            agent_threats = [
                {
                    "id": "AI-THREAT-004",
                    "owasp_id": "LLM06:2025",
                    "title": "Excessive Agent Autonomy",
                    "category": "Agentic AI Security",
                    "severity": "critical",
                    "description": "AI agents may perform unintended or harmful actions without proper human oversight or approval.",
                    "attack_vector": "Manipulating agent goals or exploiting lack of action boundaries",
                    "mitigations": [
                        "Implement human-in-the-loop for critical actions",
                        "Define strict action boundaries and permissions",
                        "Log all agent actions with full context",
                        "Implement emergency stop mechanisms"
                    ]
                },
                {
                    "id": "AI-THREAT-005",
                    "owasp_id": "AGENT02",
                    "title": "Tool/API Abuse by AI Agents",
                    "category": "Agentic AI Security",
                    "severity": "high",
                    "description": "AI agents may misuse tools or APIs they have access to, leading to data exfiltration or unauthorized actions.",
                    "attack_vector": "Exploiting agent's tool access through prompt manipulation or goal misalignment",
                    "mitigations": [
                        "Apply least privilege to agent tool access",
                        "Implement per-tool rate limiting",
                        "Validate all tool inputs and outputs",
                        "Sandbox tool execution environments"
                    ]
                },
                {
                    "id": "AI-THREAT-006",
                    "owasp_id": "AGENT03",
                    "title": "Agent Memory/Context Manipulation",
                    "category": "Agentic AI Security",
                    "severity": "high",
                    "description": "Attackers can inject malicious content into agent memory or manipulate context to influence behavior.",
                    "attack_vector": "Poisoning conversation history, RAG documents, or persistent memory stores",
                    "mitigations": [
                        "Sanitize all content before adding to memory",
                        "Implement memory integrity validation",
                        "Use separate memory stores for different trust levels",
                        "Encrypt sensitive memory contents"
                    ]
                }
            ]
            threats.extend(agent_threats)
        
        return threats
    
    async def _run_stride_analysis(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any],
        severity_threshold: str,
        parsed_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run STRIDE-based threat analysis"""
        context = self._build_context(project_data, elicitation_results, parsed_content)
        raw_threats = await self._generate_stride_threats(context)
        
        processed_threats = []
        for threat in raw_threats:
            processed = await self._process_stride_threat(threat)
            if self._meets_threshold(processed, severity_threshold):
                processed_threats.append(processed)
        
        processed_threats.sort(key=lambda t: t.get("overall_risk", 0), reverse=True)
        
        logger.info("STRIDE analysis complete", total_threats=len(processed_threats))
        
        return {
            "methodology": "STRIDE",
            "threats": processed_threats,
            "summary": {
                "total": len(processed_threats),
                "by_category": self._count_by_category(processed_threats),
                "by_severity": self._count_by_severity(processed_threats)
            }
        }
    
    async def _run_pasta_analysis(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any],
        severity_threshold: str,
        parsed_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run PASTA-based threat analysis"""
        # Include parsed content in project data for PASTA engine
        pasta_project_data = {**project_data}
        if parsed_content:
            pasta_project_data["parsed_content"] = parsed_content
        
        # Run PASTA engine
        pasta_results = self.pasta_engine.analyze(
            project_data=pasta_project_data,
            business_objectives=elicitation_results.get("assumptions", [])
        )
        
        # Get threats from PASTA analysis
        threats = pasta_results.get("threats", [])
        
        # Filter by severity threshold
        filtered_threats = [
            t for t in threats
            if self._meets_threshold(t, severity_threshold)
        ]
        
        logger.info("PASTA analysis complete", total_threats=len(filtered_threats))
        
        return {
            "methodology": "PASTA",
            "stages": pasta_results.get("stages", {}),
            "threats": filtered_threats,
            "summary": pasta_results.get("risk_summary", {
                "total": len(filtered_threats),
                "by_severity": self._count_by_severity(filtered_threats)
            })
        }
    
    def _build_context(
        self,
        project_data: Dict[str, Any],
        elicitation_results: Dict[str, Any],
        parsed_content: Optional[str] = None
    ) -> str:
        """Build context for threat analysis including actual document content"""
        parts = []
        parts.append(f"## Project: {project_data.get('project_name', 'Unknown')}")
        parts.append(f"Description: {project_data.get('description', 'N/A')}")
        
        # Include actual document content for more accurate threat identification
        if parsed_content:
            # Limit to avoid token overflow (keep first 6000 chars for threat context)
            content_preview = parsed_content[:6000]
            if len(parsed_content) > 6000:
                content_preview += "\n... [content truncated for analysis]"
            parts.append(f"\n## System Documentation\n{content_preview}")
        else:
            # Fallback: try to get parsed_content from files in project_data
            files = project_data.get("files", [])
            for f in files[:3]:
                fc = f.get("parsed_content", "")
                if fc:
                    content_preview = fc[:3000]
                    if len(fc) > 3000:
                        content_preview += "\n... [truncated]"
                    name = f.get('original_name', f.get('filename', 'unknown'))
                    parts.append(f"\n## Content from {name}\n{content_preview}")
        
        assumptions = elicitation_results.get("assumptions", [])
        if assumptions:
            parts.append("\n## Assumptions")
            for a in assumptions:
                parts.append(f"- {a}")
        
        gaps = elicitation_results.get("critical_gaps", [])
        if gaps:
            parts.append("\n## Security Areas to Focus")
            for g in gaps:
                parts.append(f"- {g}")
        
        return "\n".join(parts)
    
    async def _generate_stride_threats(self, context: str) -> List[Dict[str, Any]]:
        """Generate STRIDE threats using LLM with OWASP mappings"""
        prompt = f"""Analyze the following system and identify security threats using STRIDE methodology.
Map each threat to relevant OWASP frameworks.

{context}

For each threat identified, provide:
1. STRIDE category
2. Title (concise)
3. Description (detailed)
4. Affected component
5. Attack vector
6. DREAD scores (each 1-10)
7. At least 3 mitigation recommendations
8. OWASP framework mappings

OWASP Framework Mappings to include:
- owasp_top_10: Web security (A01-A10:2021)
- owasp_api: API security (API1-API10:2023) - if APIs involved
- owasp_llm: AI/LLM security (LLM01-LLM10:2025) - if AI components
- agentic_ai: Agent security (AGENT01-AGENT05) - if AI agents used

Identify at least 5 significant threats across different STRIDE categories.

Respond with JSON:
{{
    "threats": [
        {{
            "category": "STRIDE category",
            "title": "Threat title",
            "description": "Detailed description",
            "affected_component": "Component name",
            "attack_vector": "How the attack works",
            "dread_scores": {{
                "damage": 7,
                "reproducibility": 8,
                "exploitability": 6,
                "affected_users": 9,
                "discoverability": 5
            }},
            "mitigations": ["mitigation1", "mitigation2", "mitigation3"],
            "owasp_mappings": {{
                "owasp_top_10": ["A01:2021", "A03:2021"],
                "owasp_api": ["API1:2023"],
                "owasp_llm": [],
                "agentic_ai": []
            }}
        }}
    ]
}}"""
        
        try:
            response = await self.llm.generate(
                prompt=prompt,
                system=self.STRIDE_SYSTEM_PROMPT,
                temp=0.4,
                max_tokens=4000
            )
            result = self._parse_response(response)
            return result.get("threats", [])
        except Exception as e:
            logger.error("STRIDE threat generation failed", error=str(e))
            return self._get_default_stride_threats()
    
    async def _process_stride_threat(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Process and enrich a STRIDE threat with OWASP mappings"""
        threat_id = f"THR-{str(uuid.uuid4())[:8].upper()}"
        dread_scores = threat.get("dread_scores", {})
        
        dread_result = self.dread_engine.calculate(
            damage=dread_scores.get("damage", 5),
            reproducibility=dread_scores.get("reproducibility", 5),
            exploitability=dread_scores.get("exploitability", 5),
            affected_users=dread_scores.get("affected_users", 5),
            discoverability=dread_scores.get("discoverability", 5)
        )
        
        severity = self._calculate_severity(dread_result["score"])
        
        # Get OWASP mappings from threat or infer from STRIDE category
        owasp_mappings = threat.get("owasp_mappings", {})
        if not owasp_mappings:
            # Infer OWASP mappings from STRIDE category
            category = threat.get("category", "")
            owasp_ids = self.owasp_mapper.map_stride_to_owasp(category)
            owasp_mappings = {
                "owasp_top_10": [oid for oid in owasp_ids if oid.startswith("A")],
                "owasp_api": [oid for oid in owasp_ids if oid.startswith("API")],
                "owasp_llm": [oid for oid in owasp_ids if oid.startswith("LLM")],
                "agentic_ai": [oid for oid in owasp_ids if oid.startswith("AGENT")]
            }
        
        return {
            "id": threat_id,
            "category": threat.get("category", "Unknown"),
            "title": threat.get("title", "Unspecified Threat"),
            "description": threat.get("description", ""),
            "affected_component": threat.get("affected_component", "System"),
            "attack_vector": threat.get("attack_vector", ""),
            "dread_score": dread_scores,
            "overall_risk": dread_result["score"],
            "risk_level": dread_result["level"],
            "severity": severity,
            "mitigations": threat.get("mitigations", []),
            "owasp_mappings": owasp_mappings,
            "compliance_mappings": {}
        }
    
    def _calculate_severity(self, risk_score: float) -> str:
        if risk_score >= 8:
            return "critical"
        elif risk_score >= 6:
            return "high"
        elif risk_score >= 4:
            return "medium"
        return "low"
    
    def _meets_threshold(self, threat: Dict[str, Any], threshold: str) -> bool:
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threat_severity = threat.get("severity", "low")
        return severity_order.get(threat_severity, 0) >= severity_order.get(threshold, 0)
    
    def _count_by_category(self, threats: List[Dict]) -> Dict[str, int]:
        counts = {}
        for threat in threats:
            category = threat.get("category", "Unknown")
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def _count_by_severity(self, threats: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for threat in threats:
            severity = threat.get("severity", "low")
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _parse_response(self, response: str) -> Dict[str, Any]:
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass
        return {"threats": self._get_default_stride_threats()}
    
    def _get_default_stride_threats(self) -> List[Dict[str, Any]]:
        """Return default STRIDE threat set with OWASP mappings"""
        return [
            {
                "category": "Spoofing",
                "title": "Authentication Bypass via Token Manipulation",
                "description": "Attackers could forge or manipulate authentication tokens to impersonate legitimate users.",
                "affected_component": "Authentication Service",
                "attack_vector": "Token interception and modification, JWT signature bypass",
                "dread_scores": {"damage": 8, "reproducibility": 6, "exploitability": 5, "affected_users": 9, "discoverability": 4},
                "mitigations": ["Implement strong token signing (RS256)", "Use short-lived tokens", "Validate token integrity", "Implement token refresh rotation"],
                "owasp_mappings": {
                    "owasp_top_10": ["A07:2021"],
                    "owasp_api": ["API2:2023"],
                    "owasp_llm": [],
                    "agentic_ai": []
                }
            },
            {
                "category": "Tampering",
                "title": "SQL Injection in User Input Fields",
                "description": "Unsanitized user inputs could allow SQL injection attacks, potentially leading to data breach or system compromise.",
                "affected_component": "API Gateway",
                "attack_vector": "Malicious SQL payloads in form fields, query parameters, headers",
                "dread_scores": {"damage": 9, "reproducibility": 8, "exploitability": 7, "affected_users": 10, "discoverability": 6},
                "mitigations": ["Use parameterized queries/prepared statements", "Implement input validation with allowlists", "Apply least privilege to database access", "Use Web Application Firewall (WAF)"],
                "owasp_mappings": {
                    "owasp_top_10": ["A03:2021"],
                    "owasp_api": ["API8:2023"],
                    "owasp_llm": [],
                    "agentic_ai": []
                }
            },
            {
                "category": "Information Disclosure",
                "title": "Sensitive Data Exposure in API Responses",
                "description": "API endpoints may leak sensitive information through verbose error messages, excessive data exposure, or improper response filtering.",
                "affected_component": "REST API",
                "attack_vector": "Endpoint enumeration, error analysis, response inspection",
                "dread_scores": {"damage": 7, "reproducibility": 9, "exploitability": 8, "affected_users": 7, "discoverability": 7},
                "mitigations": ["Implement proper error handling without stack traces", "Apply response filtering/masking for PII", "Use data classification and access controls", "Implement API response schemas"],
                "owasp_mappings": {
                    "owasp_top_10": ["A01:2021", "A02:2021"],
                    "owasp_api": ["API3:2023"],
                    "owasp_llm": ["LLM02:2025"],
                    "agentic_ai": []
                }
            },
            {
                "category": "Denial of Service",
                "title": "Resource Exhaustion via Unbounded Requests",
                "description": "Lack of rate limiting and resource constraints could allow attackers to overwhelm the system with excessive requests.",
                "affected_component": "Load Balancer / API Gateway",
                "attack_vector": "High-volume request flooding, resource-intensive queries, batch operation abuse",
                "dread_scores": {"damage": 6, "reproducibility": 10, "exploitability": 9, "affected_users": 10, "discoverability": 8},
                "mitigations": ["Implement rate limiting per client/IP", "Add request throttling with backpressure", "Deploy DDoS protection", "Set resource quotas and timeouts"],
                "owasp_mappings": {
                    "owasp_top_10": ["A05:2021"],
                    "owasp_api": ["API4:2023"],
                    "owasp_llm": ["LLM10:2025"],
                    "agentic_ai": []
                }
            },
            {
                "category": "Elevation of Privilege",
                "title": "Insecure Direct Object Reference (IDOR)",
                "description": "Users could access or modify other users' resources by manipulating object identifiers without proper authorization checks.",
                "affected_component": "Resource Controller",
                "attack_vector": "Sequential ID enumeration, parameter tampering, horizontal privilege escalation",
                "dread_scores": {"damage": 8, "reproducibility": 7, "exploitability": 8, "affected_users": 8, "discoverability": 6},
                "mitigations": ["Implement object-level authorization checks", "Use non-guessable UUIDs", "Validate user ownership on every request", "Add access control logging and alerting"],
                "owasp_mappings": {
                    "owasp_top_10": ["A01:2021"],
                    "owasp_api": ["API1:2023", "API5:2023"],
                    "owasp_llm": [],
                    "agentic_ai": []
                }
            }
        ]
    
    @staticmethod
    def get_available_methodologies() -> List[Dict[str, Any]]:
        """Get list of available threat modeling methodologies"""
        return [
            {
                "id": "stride",
                "name": "STRIDE",
                "description": "Microsoft's threat modeling methodology focusing on 6 threat categories",
                "categories": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
                "best_for": "Technical threat identification, developer-focused analysis",
                "complexity": "Medium"
            },
            {
                "id": "pasta",
                "name": "PASTA",
                "full_name": "Process for Attack Simulation and Threat Analysis",
                "description": "7-stage risk-centric methodology focusing on business objectives and threat agents",
                "stages": [
                    "Define Objectives",
                    "Define Technical Scope", 
                    "Application Decomposition",
                    "Threat Analysis",
                    "Vulnerability Analysis",
                    "Attack Modeling",
                    "Risk & Impact Analysis"
                ],
                "best_for": "Enterprise applications, risk-driven decisions, stakeholder communication",
                "complexity": "High"
            },
            {
                "id": "maestro",
                "name": "MAESTRO",
                "full_name": "Multi-Agent Environment Security Threat Risk & Outcome",
                "description": "CSA's Agentic AI threat modeling framework for AI-powered and multi-agent systems",
                "categories": [
                    "Autonomous Action Abuse",
                    "Multi-Agent Coordination Attacks", 
                    "Tool/MCP Exploitation",
                    "Memory/Context Manipulation",
                    "Goal/Objective Hijacking",
                    "LLM Decision Trust Exploitation"
                ],
                "best_for": "AI agents, LLM applications, multi-agent systems, autonomous workflows",
                "complexity": "High",
                "reference": "https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro"
            }
        ]
