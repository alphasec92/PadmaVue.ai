"""
Security Analysis API Endpoints
Handles threat modeling with persistent storage of all results
"""

import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import structlog

from app.config import settings
from app.agents.orchestrator import SecurityOrchestrator
from app.agents.threat import ThreatAgent
from app.api.settings import get_runtime_config
from app.storage.repository import (
    project_repo,
    analysis_repo,
    threat_repo,
    report_repo,
    AnalysisStatus,
)
from app.core.logging import audit_logger, ai_logger
from app.core.exceptions import (
    AnalysisError,
    classify_error,
    ErrorCategory,
    LLMError,
    DatabaseError,
    NotFoundError,
)
from app.utils.validation import (
    validate_methodology,
    validate_severity,
    validate_analysis_type,
    validate_compliance_frameworks,
)

logger = structlog.get_logger()
router = APIRouter()


# ===========================================
# Models
# ===========================================

class AnalysisRequest(BaseModel):
    """Request model for security analysis"""
    project_id: str
    analysis_type: str = Field(default="full")
    methodology: str = Field(default="stride")  # Primary: "stride" or "pasta"
    # MAESTRO (Agentic AI) overlay settings
    include_maestro: bool = Field(default=False, description="Include MAESTRO agentic AI threat analysis")
    force_maestro: bool = Field(default=False, description="Force MAESTRO even if not auto-detected")
    maestro_confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0, description="Confidence threshold for MAESTRO applicability")
    # Other settings
    include_dfd: bool = Field(default=True)
    include_compliance: bool = Field(default=True)
    include_devsecops: bool = Field(default=True)
    compliance_frameworks: List[str] = Field(default=["NIST_800_53", "OWASP_ASVS"])
    severity_threshold: str = Field(default="low")


class ThreatFinding(BaseModel):
    """Model for a threat finding"""
    id: str
    category: str
    title: str
    description: str
    affected_component: str
    attack_vector: str
    dread_score: Dict[str, float]
    overall_risk: float
    severity: str
    mitigations: List[str]
    compliance_mappings: Dict[str, List[str]]
    threat_agent: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    likelihood: Optional[float] = None
    impact: Optional[float] = None
    business_impact: Optional[str] = None


class MaestroApplicabilityResponse(BaseModel):
    """MAESTRO applicability decision with evidence"""
    applicable: bool
    confidence: float
    status: str  # "detected" | "not_detected" | "forced"
    reasons: List[str]
    evidence: List[Dict[str, Any]]
    signals: Optional[Dict[str, Any]] = None
    checked_at: Optional[str] = None


class AnalysisResponse(BaseModel):
    """Response model for security analysis"""
    analysis_id: str
    project_id: str
    methodology: str
    status: str
    created_at: str
    completed_at: Optional[str] = None
    summary: Dict[str, Any]
    threats: List[ThreatFinding]
    compliance_summary: Dict[str, Any]
    dfd_mermaid: Optional[str] = None
    devsecops_rules: Optional[Dict[str, Any]] = None
    pasta_stages: Optional[Dict[str, Any]] = None
    # MAESTRO (Agentic AI) results
    maestro_applicability: Optional[MaestroApplicabilityResponse] = None
    maestro_threats: Optional[List[Dict[str, Any]]] = None


class AnalysisStatus(BaseModel):
    """Status model for analysis progress"""
    analysis_id: str
    project_id: str
    methodology: str
    status: str
    progress: float
    current_step: str
    steps_completed: List[str]


class MethodologyInfo(BaseModel):
    """Information about a threat modeling methodology"""
    id: str
    name: str
    description: str
    best_for: str
    complexity: str


# ===========================================
# Endpoints
# ===========================================

@router.get("/list")
async def list_analyses(limit: int = 50, include_project_info: bool = True):
    """List all analyses with project info, most recent first."""
    try:
        analyses_list = await analysis_repo.list_all(limit=limit)
        
        # Enrich with project names if requested
        if include_project_info:
            for analysis in analyses_list:
                project_id = analysis.get("project_id")
                if project_id:
                    project = await project_repo.get_project(project_id)
                    if project:
                        analysis["project_name"] = project.name
                        analysis["project_description"] = project.description
                    else:
                        analysis["project_name"] = project_id[:8] + "..."
                        analysis["project_description"] = ""
        
        return {"analyses": analyses_list, "total": len(analyses_list)}
    except Exception as e:
        logger.error("Failed to list analyses", error=str(e))
        return {"analyses": [], "total": 0}


@router.get("/methodologies", response_model=List[MethodologyInfo])
async def get_methodologies():
    """Get available threat modeling methodologies."""
    methodologies = ThreatAgent.get_available_methodologies()
    return [
        MethodologyInfo(
            id=m["id"],
            name=m["name"],
            description=m["description"],
            best_for=m["best_for"],
            complexity=m["complexity"]
        )
        for m in methodologies
    ]


@router.post("", response_model=AnalysisResponse)
async def analyze_project(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks
):
    """
    Run security analysis on an ingested project.
    
    All results are persisted for later retrieval:
    - Analysis metadata and status
    - Individual threats
    - Compliance mappings
    - Generated diagrams and rules
    - Agent interaction logs
    """
    # Validate inputs
    try:
        methodology = validate_methodology(request.methodology)
        severity_threshold = validate_severity(request.severity_threshold)
        analysis_type = validate_analysis_type(request.analysis_type)
        frameworks = validate_compliance_frameworks(request.compliance_frameworks)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Get project
    project = await project_repo.get_project(request.project_id)
    if not project:
        error = NotFoundError("project", context={"project_id": request.project_id})
        logger.warning("Project not found for analysis", **error.to_log_context())
        return JSONResponse(status_code=404, content=error.to_response())
    
    # Create analysis record
    analysis = await analysis_repo.create_analysis(
        project_id=request.project_id,
        methodology=methodology
    )
    
    logger.info("Starting security analysis",
                analysis_id=analysis.id,
                project_id=request.project_id,
                methodology=methodology)
    
    # Log AI interaction start
    ai_logger.log_agent_action(
        agent_name="orchestrator",
        action="analysis_start",
        project_id=request.project_id,
        analysis_id=analysis.id,
        methodology=methodology
    )
    
    try:
        # Update status to in_progress
        await analysis_repo.update_analysis(
            analysis.id,
            status="in_progress"
        )
        
        # Initialize orchestrator with runtime LLM config
        runtime_config = get_runtime_config()
        orchestrator = SecurityOrchestrator(runtime_config=runtime_config)
        
        # Prepare project data
        project_data = {
            'project_id': project.id,
            'project_name': project.name,
            'description': project.description,
            'files': project.files,
            'metadata': project.metadata
        }
        
        # Run analysis
        result = await orchestrator.analyze(
            project_id=request.project_id,
            project_data=project_data,
            analysis_type=analysis_type,
            methodology=methodology,
            include_dfd=request.include_dfd,
            include_compliance=request.include_compliance,
            include_devsecops=request.include_devsecops,
            compliance_frameworks=frameworks,
            severity_threshold=severity_threshold,
            # MAESTRO (Agentic AI) overlay parameters
            include_maestro=request.include_maestro,
            force_maestro=request.force_maestro,
            maestro_confidence_threshold=request.maestro_confidence_threshold
        )
        
        # Save threats individually for detailed tracking
        if result.get('threats'):
            await threat_repo.save_threats(analysis.id, result['threats'])
        
        # Complete the analysis with results
        await analysis_repo.complete_analysis(analysis.id, result)
        
        # Add agent logs
        await analysis_repo.add_agent_log(
            analysis.id,
            agent="orchestrator",
            action="analysis_complete",
            data={
                'threats_count': len(result.get('threats', [])),
                'methodology': methodology,
                'summary': result.get('summary', {})
            }
        )
        
        # Create report
        await report_repo.create_report(
            project_id=request.project_id,
            analysis_id=analysis.id,
            report_type="security_analysis",
            content=result,
            fmt="json"
        )
        
        # Get updated analysis
        final_analysis = await analysis_repo.get_analysis(analysis.id)
        
        # Audit log
        audit_logger.log_data_access(
            user_id="api",
            data_type="analysis",
            record_id=analysis.id,
            action="create",
            methodology=methodology,
            threats_count=len(result.get('threats', []))
        )
        
        # Log AI interaction complete
        ai_logger.log_agent_action(
            agent_name="orchestrator",
            action="analysis_complete",
            project_id=request.project_id,
            analysis_id=analysis.id,
            threats_found=len(result.get('threats', []))
        )
        
        logger.info("Security analysis complete",
                   analysis_id=analysis.id,
                   methodology=methodology,
                   threats_found=len(result.get('threats', [])))
        
        # Build MAESTRO applicability response if present
        maestro_applicability = None
        if result.get("maestro_applicability"):
            maestro_applicability = MaestroApplicabilityResponse(
                **result["maestro_applicability"]
            )
        
        return AnalysisResponse(
            analysis_id=final_analysis.id,
            project_id=final_analysis.project_id,
            methodology=methodology.upper(),
            status=final_analysis.status,
            created_at=final_analysis.created_at,
            completed_at=final_analysis.completed_at,
            summary=final_analysis.summary,
            threats=final_analysis.threats,
            compliance_summary=final_analysis.compliance_summary,
            dfd_mermaid=final_analysis.dfd_mermaid,
            devsecops_rules=final_analysis.devsecops_rules,
            pasta_stages=final_analysis.pasta_stages if methodology == "pasta" else None,
            # MAESTRO results
            maestro_applicability=maestro_applicability,
            maestro_threats=result.get("maestro_threats", [])
        )
        
    except AnalysisError as e:
        # Known error - update status and return user-friendly message
        await analysis_repo.update_analysis(
            analysis.id,
            status="failed",
            metadata={
                'error': e.user_message,
                'error_category': e.category.value,
                'technical_details': e.technical_details
            }
        )
        
        logger.error(
            "Analysis failed",
            analysis_id=analysis.id,
            **e.to_log_context()
        )
        
        return JSONResponse(
            status_code=500,
            content=e.to_response()
        )
        
    except Exception as e:
        # Unknown error - classify and return user-friendly message
        classified_error = classify_error(e, context={
            'analysis_id': analysis.id,
            'project_id': request.project_id,
            'methodology': methodology
        })
        
        # Update analysis status to failed
        await analysis_repo.update_analysis(
            analysis.id,
            status="failed",
            metadata={
                'error': classified_error.user_message,
                'error_category': classified_error.category.value,
                'technical_details': classified_error.technical_details
            }
        )
        
        # Log full technical details for debugging
        logger.error(
            "Analysis failed",
            analysis_id=analysis.id,
            error_type=type(e).__name__,
            error_message=str(e),
            **classified_error.to_log_context()
        )
        
        return JSONResponse(
            status_code=500,
            content=classified_error.to_response()
        )


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(analysis_id: str):
    """Get analysis results by ID"""
    analysis = await analysis_repo.get_analysis(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return AnalysisResponse(
        analysis_id=analysis.id,
        project_id=analysis.project_id,
        methodology=analysis.methodology.upper(),
        status=analysis.status,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at,
        summary=analysis.summary,
        threats=analysis.threats,
        compliance_summary=analysis.compliance_summary,
        dfd_mermaid=analysis.dfd_mermaid,
        devsecops_rules=analysis.devsecops_rules,
        pasta_stages=analysis.pasta_stages
    )


@router.get("/{analysis_id}/status")
async def get_analysis_status(analysis_id: str):
    """Get analysis status and progress"""
    analysis = await analysis_repo.get_analysis(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    progress = 1.0 if analysis.status == "completed" else 0.5 if analysis.status == "in_progress" else 0.0
    
    return {
        "analysis_id": analysis_id,
        "project_id": analysis.project_id,
        "methodology": analysis.methodology,
        "status": analysis.status,
        "progress": progress,
        "created_at": analysis.created_at,
        "completed_at": analysis.completed_at
    }


@router.get("/{analysis_id}/threats")
async def get_analysis_threats(analysis_id: str):
    """Get detailed threats for an analysis"""
    analysis = await analysis_repo.get_analysis(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Get threats from dedicated storage
    threats = await threat_repo.get_threats_by_analysis(analysis_id)
    
    return {
        "analysis_id": analysis_id,
        "threats": threats if threats else analysis.threats,
        "total": len(threats) if threats else len(analysis.threats)
    }


@router.get("/{analysis_id}/logs")
async def get_analysis_logs(analysis_id: str):
    """Get agent interaction logs for an analysis"""
    analysis = await analysis_repo.get_analysis(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return {
        "analysis_id": analysis_id,
        "logs": analysis.agent_logs,
        "total": len(analysis.agent_logs)
    }


@router.get("/project/{project_id}")
async def get_project_analyses(project_id: str):
    """Get all analyses for a project"""
    analyses = await analysis_repo.get_project_analyses(project_id)
    
    return {
        "project_id": project_id,
        "analyses": [
            {
                "id": a.id,
                "methodology": a.methodology,
                "status": a.status,
                "created_at": a.created_at,
                "completed_at": a.completed_at,
                "threats_count": len(a.threats)
            }
            for a in analyses
        ],
        "total": len(analyses)
    }


@router.get("")
async def get_analyses_root(limit: int = 20):
    """List all analyses (root endpoint)."""
    try:
        analyses_list = await analysis_repo.list_all(limit=limit)
        return {"analyses": analyses_list, "total": len(analyses_list)}
    except Exception as e:
        logger.error("Failed to list analyses", error=str(e))
        return {"analyses": [], "total": 0}


@router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: str):
    """Delete an analysis"""
    analysis = await analysis_repo.get_analysis(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    await analysis_repo.delete(analysis_id)
    
    # Audit log
    audit_logger.log_data_access(
        user_id="api",
        data_type="analysis",
        record_id=analysis_id,
        action="delete"
    )
    
    logger.info("Analysis deleted", analysis_id=analysis_id)
    
    return {"status": "deleted", "analysis_id": analysis_id}


@router.post("/compare")
async def compare_methodologies(
    project_id: str,
    severity_threshold: str = "low"
):
    """Run both STRIDE and PASTA analyses and compare results."""
    project = await project_repo.get_project(project_id)
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    project_data = {
        'project_id': project.id,
        'project_name': project.name,
        'description': project.description,
        'files': project.files,
        'metadata': project.metadata
    }
    
    # Initialize orchestrator with runtime LLM config
    runtime_config = get_runtime_config()
    orchestrator = SecurityOrchestrator(runtime_config=runtime_config)
    
    # Run STRIDE
    stride_result = await orchestrator.analyze(
        project_id=project_id,
        project_data=project_data,
        methodology="stride",
        severity_threshold=severity_threshold
    )
    
    # Run PASTA
    pasta_result = await orchestrator.analyze(
        project_id=project_id,
        project_data=project_data,
        methodology="pasta",
        severity_threshold=severity_threshold
    )
    
    comparison = {
        "project_id": project_id,
        "stride": {
            "total_threats": len(stride_result.get("threats", [])),
            "by_severity": stride_result.get("summary", {}).get("by_severity", {}),
            "average_risk": stride_result.get("summary", {}).get("average_risk", 0)
        },
        "pasta": {
            "total_threats": len(pasta_result.get("threats", [])),
            "by_severity": pasta_result.get("summary", {}).get("by_severity", {}),
            "average_risk": pasta_result.get("summary", {}).get("average_risk", 0)
        }
    }
    
    return comparison


# Legacy compatibility - use analysis_repo instead
analysis_store = {}
