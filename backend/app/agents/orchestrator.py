"""
Security Analysis Orchestrator
LangGraph-based multi-agent orchestration for security review
Supports both STRIDE and PASTA methodologies
"""

from typing import Dict, Any, List, Optional, TypedDict, Annotated
from enum import Enum
import json

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
import structlog

from app.config import settings
from app.services.llm_provider import get_llm_provider
from app.agents.elicitation import ElicitationAgent
from app.agents.threat import ThreatAgent
from app.agents.compliance import ComplianceAgent
from app.agents.diagram import DiagramAgent
from app.agents.devsecops import DevSecOpsAgent
from app.agents.guardrail import GuardrailAgent

logger = structlog.get_logger()


class AnalysisPhase(str, Enum):
    """Phases of the security analysis"""
    ELICITATION = "elicitation"
    THREAT_MODELING = "threat_modeling"
    COMPLIANCE = "compliance"
    DIAGRAM = "diagram"
    DEVSECOPS = "devsecops"
    GUARDRAIL = "guardrail"
    COMPLETE = "complete"


class AnalysisState(TypedDict):
    """State schema for the analysis workflow"""
    # Input data
    project_id: str
    project_data: Dict[str, Any]
    analysis_type: str
    methodology: str  # "stride" or "pasta"
    
    # Configuration
    include_dfd: bool
    include_compliance: bool
    include_devsecops: bool
    compliance_frameworks: List[str]
    severity_threshold: str
    
    # Processing state
    current_phase: str
    messages: Annotated[List[Dict[str, Any]], add_messages]
    
    # Results from each agent
    elicitation_results: Optional[Dict[str, Any]]
    threat_results: Optional[Dict[str, Any]]
    compliance_results: Optional[Dict[str, Any]]
    diagram_results: Optional[Dict[str, Any]]
    devsecops_results: Optional[Dict[str, Any]]
    guardrail_results: Optional[Dict[str, Any]]
    
    # Final output
    final_results: Optional[Dict[str, Any]]
    errors: List[str]


class SecurityOrchestrator:
    """
    LangGraph-based orchestrator for security analysis.
    
    Supports both STRIDE and PASTA threat modeling methodologies.
    
    Agents:
    1. Elicitation Agent - Identifies missing information
    2. Threat Agent - STRIDE/PASTA modeling & DREAD scoring
    3. Compliance Agent - NIST/ASVS mapping
    4. Diagram Agent - Mermaid DFD generation
    5. DevSecOps Agent - Rule generation
    6. Guardrail Agent - Output validation
    """
    
    def __init__(self):
        self.llm = get_llm_provider()
        
        # Initialize agents
        self.elicitation_agent = ElicitationAgent(self.llm)
        self.threat_agent = ThreatAgent(self.llm)
        self.compliance_agent = ComplianceAgent(self.llm)
        self.diagram_agent = DiagramAgent(self.llm)
        self.devsecops_agent = DevSecOpsAgent(self.llm)
        self.guardrail_agent = GuardrailAgent(self.llm)
        
        # Build the graph
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(AnalysisState)
        
        # Add nodes for each agent
        workflow.add_node("elicitation", self._run_elicitation)
        workflow.add_node("threat_modeling", self._run_threat_modeling)
        workflow.add_node("compliance", self._run_compliance)
        workflow.add_node("diagram", self._run_diagram)
        workflow.add_node("devsecops", self._run_devsecops)
        workflow.add_node("guardrail", self._run_guardrail)
        workflow.add_node("finalize", self._finalize_results)
        
        # Set entry point
        workflow.set_entry_point("elicitation")
        
        # Add edges
        workflow.add_edge("elicitation", "threat_modeling")
        workflow.add_edge("threat_modeling", "compliance")
        
        workflow.add_conditional_edges(
            "compliance",
            self._should_generate_diagram,
            {True: "diagram", False: "devsecops"}
        )
        
        workflow.add_conditional_edges(
            "diagram",
            self._should_generate_devsecops,
            {True: "devsecops", False: "guardrail"}
        )
        
        workflow.add_edge("devsecops", "guardrail")
        workflow.add_edge("guardrail", "finalize")
        workflow.add_edge("finalize", END)
        
        return workflow.compile()
    
    def _should_generate_diagram(self, state: AnalysisState) -> bool:
        return state.get("include_dfd", True)
    
    def _should_generate_devsecops(self, state: AnalysisState) -> bool:
        return state.get("include_devsecops", True)
    
    async def _run_elicitation(self, state: AnalysisState) -> Dict[str, Any]:
        """Run elicitation agent"""
        logger.info("Running elicitation agent", project_id=state["project_id"])
        
        try:
            results = await self.elicitation_agent.run(
                project_data=state["project_data"]
            )
            return {
                "current_phase": AnalysisPhase.THREAT_MODELING,
                "elicitation_results": results,
                "messages": [{"role": "assistant", "content": f"Elicitation complete"}]
            }
        except Exception as e:
            logger.error("Elicitation failed", error=str(e))
            return {
                "errors": state.get("errors", []) + [f"Elicitation error: {str(e)}"],
                "elicitation_results": {"questions": [], "assumptions": []}
            }
    
    async def _run_threat_modeling(self, state: AnalysisState) -> Dict[str, Any]:
        """Run threat modeling agent with selected methodology"""
        methodology = state.get("methodology", "stride")
        logger.info(f"Running {methodology.upper()} threat modeling", project_id=state["project_id"])
        
        try:
            results = await self.threat_agent.run(
                project_data=state["project_data"],
                elicitation_results=state.get("elicitation_results", {}),
                severity_threshold=state.get("severity_threshold", "low"),
                methodology=methodology
            )
            
            threat_count = len(results.get("threats", []))
            
            return {
                "current_phase": AnalysisPhase.COMPLIANCE,
                "threat_results": results,
                "messages": [{"role": "assistant", "content": f"{methodology.upper()} analysis complete: {threat_count} threats"}]
            }
        except Exception as e:
            logger.error("Threat modeling failed", error=str(e))
            return {
                "errors": state.get("errors", []) + [f"Threat modeling error: {str(e)}"],
                "threat_results": {"threats": [], "methodology": methodology}
            }
    
    async def _run_compliance(self, state: AnalysisState) -> Dict[str, Any]:
        """Run compliance mapping agent"""
        logger.info("Running compliance agent", project_id=state["project_id"])
        
        if not state.get("include_compliance", True):
            return {"current_phase": AnalysisPhase.DIAGRAM, "compliance_results": {}}
        
        try:
            results = await self.compliance_agent.run(
                threat_results=state.get("threat_results", {}),
                frameworks=state.get("compliance_frameworks", ["NIST_800_53", "OWASP_ASVS"])
            )
            return {
                "current_phase": AnalysisPhase.DIAGRAM,
                "compliance_results": results,
                "messages": [{"role": "assistant", "content": "Compliance mapping complete"}]
            }
        except Exception as e:
            logger.error("Compliance mapping failed", error=str(e))
            return {
                "errors": state.get("errors", []) + [f"Compliance error: {str(e)}"],
                "compliance_results": {}
            }
    
    async def _run_diagram(self, state: AnalysisState) -> Dict[str, Any]:
        """Run diagram generation agent"""
        logger.info("Running diagram agent", project_id=state["project_id"])
        
        try:
            results = await self.diagram_agent.run(
                project_data=state["project_data"],
                threat_results=state.get("threat_results", {})
            )
            return {
                "current_phase": AnalysisPhase.DEVSECOPS,
                "diagram_results": results,
                "messages": [{"role": "assistant", "content": "DFD diagram generated"}]
            }
        except Exception as e:
            logger.error("Diagram generation failed", error=str(e))
            return {
                "errors": state.get("errors", []) + [f"Diagram error: {str(e)}"],
                "diagram_results": {}
            }
    
    async def _run_devsecops(self, state: AnalysisState) -> Dict[str, Any]:
        """Run DevSecOps rule generation agent"""
        logger.info("Running DevSecOps agent", project_id=state["project_id"])
        
        try:
            results = await self.devsecops_agent.run(
                threat_results=state.get("threat_results", {}),
                compliance_results=state.get("compliance_results", {})
            )
            return {
                "current_phase": AnalysisPhase.GUARDRAIL,
                "devsecops_results": results,
                "messages": [{"role": "assistant", "content": "DevSecOps rules generated"}]
            }
        except Exception as e:
            logger.error("DevSecOps generation failed", error=str(e))
            return {
                "errors": state.get("errors", []) + [f"DevSecOps error: {str(e)}"],
                "devsecops_results": {}
            }
    
    async def _run_guardrail(self, state: AnalysisState) -> Dict[str, Any]:
        """Run guardrail validation agent"""
        logger.info("Running guardrail agent", project_id=state["project_id"])
        
        try:
            results = await self.guardrail_agent.run(
                threat_results=state.get("threat_results", {}),
                compliance_results=state.get("compliance_results", {}),
                devsecops_results=state.get("devsecops_results", {})
            )
            return {
                "current_phase": AnalysisPhase.COMPLETE,
                "guardrail_results": results,
                "messages": [{"role": "assistant", "content": "Guardrail validation complete"}]
            }
        except Exception as e:
            logger.error("Guardrail validation failed", error=str(e))
            return {
                "errors": state.get("errors", []) + [f"Guardrail error: {str(e)}"],
                "guardrail_results": {"validated": True, "warnings": []}
            }
    
    async def _finalize_results(self, state: AnalysisState) -> Dict[str, Any]:
        """Finalize and compile all results"""
        logger.info("Finalizing results", project_id=state["project_id"])
        
        threat_results = state.get("threat_results", {})
        threats = threat_results.get("threats", [])
        methodology = state.get("methodology", "stride")
        
        # Format threats for output
        formatted_threats = []
        for threat in threats:
            formatted_threat = {
                "id": threat.get("id", ""),
                "category": threat.get("category", ""),
                "title": threat.get("title", ""),
                "description": threat.get("description", ""),
                "affected_component": threat.get("affected_component", ""),
                "attack_vector": threat.get("attack_vector", ""),
                "dread_score": threat.get("dread_score", {}),
                "overall_risk": threat.get("overall_risk", 5.0),
                "severity": threat.get("severity", "medium"),
                "mitigations": threat.get("mitigations", []),
                "compliance_mappings": threat.get("compliance_mappings", {})
            }
            
            # Add PASTA-specific fields
            if methodology == "pasta":
                formatted_threat["threat_agent"] = threat.get("threat_agent")
                formatted_threat["affected_assets"] = threat.get("affected_assets", [])
                formatted_threat["likelihood"] = threat.get("likelihood")
                formatted_threat["impact"] = threat.get("impact")
                formatted_threat["business_impact"] = threat.get("business_impact")
            
            formatted_threats.append(formatted_threat)
        
        # Build summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for threat in formatted_threats:
            severity = threat.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Compile final results
        final_results = {
            "methodology": methodology.upper(),
            "summary": {
                "total_threats": len(formatted_threats),
                "by_severity": severity_counts,
                "by_category": self._count_by_category(formatted_threats),
                "average_risk": self._calculate_average_risk(formatted_threats),
                "errors": state.get("errors", [])
            },
            "threats": formatted_threats,
            "compliance_summary": state.get("compliance_results", {}),
            "dfd_mermaid": state.get("diagram_results", {}).get("mermaid_code"),
            "devsecops_rules": state.get("devsecops_results", {})
        }
        
        # Add PASTA stages if applicable
        if methodology == "pasta":
            final_results["pasta_stages"] = threat_results.get("stages", {})
        
        return {
            "current_phase": AnalysisPhase.COMPLETE,
            "final_results": final_results
        }
    
    def _count_by_category(self, threats: List[Dict]) -> Dict[str, int]:
        counts = {}
        for threat in threats:
            category = threat.get("category", "Unknown")
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def _calculate_average_risk(self, threats: List[Dict]) -> float:
        if not threats:
            return 0.0
        total_risk = sum(t.get("overall_risk", 5.0) for t in threats)
        return round(total_risk / len(threats), 2)
    
    async def analyze(
        self,
        project_id: str,
        project_data: Dict[str, Any],
        analysis_type: str = "full",
        methodology: str = "stride",
        include_dfd: bool = True,
        include_compliance: bool = True,
        include_devsecops: bool = True,
        compliance_frameworks: List[str] = None,
        severity_threshold: str = "low"
    ) -> Dict[str, Any]:
        """
        Run the full security analysis workflow.
        
        Args:
            project_id: Project identifier
            project_data: Project metadata and content
            analysis_type: Type of analysis
            methodology: "stride" or "pasta"
            include_dfd: Generate DFD diagram
            include_compliance: Include compliance mapping
            include_devsecops: Generate DevSecOps rules
            compliance_frameworks: List of compliance frameworks
            severity_threshold: Minimum severity to report
        
        Returns:
            Complete analysis results
        """
        if compliance_frameworks is None:
            compliance_frameworks = ["NIST_800_53", "OWASP_ASVS"]
        
        initial_state: AnalysisState = {
            "project_id": project_id,
            "project_data": project_data,
            "analysis_type": analysis_type,
            "methodology": methodology.lower(),
            "include_dfd": include_dfd,
            "include_compliance": include_compliance,
            "include_devsecops": include_devsecops,
            "compliance_frameworks": compliance_frameworks,
            "severity_threshold": severity_threshold,
            "current_phase": AnalysisPhase.ELICITATION,
            "messages": [],
            "elicitation_results": None,
            "threat_results": None,
            "compliance_results": None,
            "diagram_results": None,
            "devsecops_results": None,
            "guardrail_results": None,
            "final_results": None,
            "errors": []
        }
        
        logger.info("Starting security analysis workflow",
                   project_id=project_id,
                   methodology=methodology,
                   analysis_type=analysis_type)
        
        final_state = await self.graph.ainvoke(initial_state)
        
        logger.info("Security analysis complete",
                   project_id=project_id,
                   methodology=methodology,
                   threats_found=len(final_state.get("final_results", {}).get("threats", [])))
        
        return final_state.get("final_results", {})
