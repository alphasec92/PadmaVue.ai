"""
Report Generation API Endpoints
Generate and retrieve security reports with full data persistence
"""

from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import structlog

from app.storage.repository import (
    project_repo,
    analysis_repo,
    report_repo,
    ReportData,
)
from app.core.logging import audit_logger

logger = structlog.get_logger()
router = APIRouter()


# ===========================================
# Models
# ===========================================

class ReportRequest(BaseModel):
    """Request model for report generation"""
    project_id: str
    analysis_id: Optional[str] = None
    report_type: str = "full"  # full, executive, technical, compliance
    format: str = "json"  # json, md, html


class ReportResponse(BaseModel):
    """Response model for report"""
    report_id: str
    project_id: str
    analysis_id: str
    report_type: str
    created_at: str
    format: str
    file_path: Optional[str] = None


# ===========================================
# Endpoints
# ===========================================

@router.get("/{project_id}")
async def get_project_report(
    project_id: str,
    report_type: str = "full",
    format: str = "json"
):
    """
    Get or generate a report for a project.
    
    Report types:
    - full: Complete security analysis report
    - executive: High-level summary for executives
    - technical: Detailed technical findings
    - compliance: Compliance-focused report
    
    All reports are stored for later retrieval.
    """
    # Get project
    project = await project_repo.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get latest analysis
    analyses = await analysis_repo.get_project_analyses(project_id)
    if not analyses:
        raise HTTPException(
            status_code=404, 
            detail="No analysis found for this project. Run analysis first."
        )
    
    latest_analysis = analyses[0]  # Already sorted by created_at desc
    
    # Check for existing report
    existing_reports = await report_repo.get_project_reports(project_id)
    for report in existing_reports:
        if (report.analysis_id == latest_analysis.id and 
            report.report_type == report_type and 
            report.format == format):
            
            logger.info("Returning existing report", report_id=report.id)
            return await _format_report_response(report, latest_analysis)
    
    # Generate new report
    report_content = _generate_report_content(
        project, 
        latest_analysis, 
        report_type
    )
    
    # Save report
    report = await report_repo.create_report(
        project_id=project_id,
        analysis_id=latest_analysis.id,
        report_type=report_type,
        content=report_content,
        format=format
    )
    
    # Audit log
    audit_logger.log_data_access(
        user_id="api",
        data_type="report",
        record_id=report.id,
        action="generate",
        report_type=report_type
    )
    
    logger.info("Report generated",
               report_id=report.id,
               project_id=project_id,
               type=report_type)
    
    return await _format_report_response(report, latest_analysis)


@router.get("/{project_id}/download/{report_id}")
async def download_report(project_id: str, report_id: str):
    """Download a generated report file"""
    report = await report_repo.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if report.project_id != project_id:
        raise HTTPException(status_code=403, detail="Report does not belong to this project")
    
    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not available")
    
    # Audit log
    audit_logger.log_data_access(
        user_id="api",
        data_type="report",
        record_id=report_id,
        action="download"
    )
    
    return FileResponse(
        path=report.file_path,
        filename=f"security_report_{report_id}.{report.format}",
        media_type="application/octet-stream"
    )


@router.get("/{project_id}/history")
async def get_report_history(project_id: str):
    """Get all reports for a project"""
    project = await project_repo.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    reports = await report_repo.get_project_reports(project_id)
    
    return {
        "project_id": project_id,
        "reports": [
            {
                "id": r.id,
                "analysis_id": r.analysis_id,
                "report_type": r.report_type,
                "format": r.format,
                "created_at": r.created_at,
                "has_file": bool(r.file_path)
            }
            for r in reports
        ],
        "total": len(reports)
    }


@router.post("/generate")
async def generate_report(request: ReportRequest):
    """Generate a new report"""
    # Get project
    project = await project_repo.get_project(request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get analysis
    if request.analysis_id:
        analysis = await analysis_repo.get_analysis(request.analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
    else:
        analyses = await analysis_repo.get_project_analyses(request.project_id)
        if not analyses:
            raise HTTPException(status_code=404, detail="No analysis found")
        analysis = analyses[0]
    
    # Generate report content
    report_content = _generate_report_content(
        project,
        analysis,
        request.report_type
    )
    
    # Save report
    report = await report_repo.create_report(
        project_id=request.project_id,
        analysis_id=analysis.id,
        report_type=request.report_type,
        content=report_content,
        format=request.format
    )
    
    logger.info("Report generated",
               report_id=report.id,
               type=request.report_type)
    
    return ReportResponse(
        report_id=report.id,
        project_id=report.project_id,
        analysis_id=report.analysis_id,
        report_type=report.report_type,
        created_at=report.created_at,
        format=report.format,
        file_path=report.file_path
    )


# ===========================================
# Helper Functions
# ===========================================

def _generate_report_content(project, analysis, report_type: str) -> dict:
    """Generate report content based on type"""
    
    base_content = {
        "report_type": report_type,
        "generated_at": datetime.utcnow().isoformat(),
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description
        },
        "analysis": {
            "id": analysis.id,
            "methodology": analysis.methodology,
            "status": analysis.status,
            "created_at": analysis.created_at,
            "completed_at": analysis.completed_at
        }
    }
    
    if report_type == "executive":
        return {
            **base_content,
            "summary": analysis.summary,
            "risk_overview": _generate_risk_overview(analysis.threats),
            "key_findings": _get_top_threats(analysis.threats, 5),
            "recommendations": _generate_recommendations(analysis.threats)
        }
    
    elif report_type == "technical":
        return {
            **base_content,
            "summary": analysis.summary,
            "threats": analysis.threats,
            "dfd_mermaid": analysis.dfd_mermaid,
            "devsecops_rules": analysis.devsecops_rules,
            "compliance_mappings": analysis.compliance_summary
        }
    
    elif report_type == "compliance":
        return {
            **base_content,
            "compliance_summary": analysis.compliance_summary,
            "threats_by_control": _group_threats_by_control(analysis.threats),
            "remediation_priority": _generate_remediation_priority(analysis.threats)
        }
    
    else:  # full
        return {
            **base_content,
            "summary": analysis.summary,
            "threats": analysis.threats,
            "compliance_summary": analysis.compliance_summary,
            "dfd_mermaid": analysis.dfd_mermaid,
            "devsecops_rules": analysis.devsecops_rules,
            "pasta_stages": analysis.pasta_stages,
            "agent_logs": analysis.agent_logs
        }


def _generate_risk_overview(threats: list) -> dict:
    """Generate risk overview from threats"""
    if not threats:
        return {"total": 0, "average_risk": 0, "by_severity": {}}
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_risk = 0
    
    for threat in threats:
        severity = threat.get("severity", "medium").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        total_risk += threat.get("overall_risk", 5)
    
    return {
        "total": len(threats),
        "average_risk": round(total_risk / len(threats), 2),
        "by_severity": severity_counts,
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"]
    }


def _get_top_threats(threats: list, count: int) -> list:
    """Get top N threats by risk"""
    sorted_threats = sorted(
        threats, 
        key=lambda t: t.get("overall_risk", 0), 
        reverse=True
    )
    return [
        {
            "title": t.get("title"),
            "severity": t.get("severity"),
            "risk": t.get("overall_risk"),
            "category": t.get("category")
        }
        for t in sorted_threats[:count]
    ]


def _generate_recommendations(threats: list) -> list:
    """Generate recommendations from threats"""
    recommendations = []
    seen = set()
    
    for threat in sorted(threats, key=lambda t: t.get("overall_risk", 0), reverse=True):
        for mitigation in threat.get("mitigations", []):
            if mitigation not in seen:
                recommendations.append({
                    "action": mitigation,
                    "priority": threat.get("severity", "medium"),
                    "related_threat": threat.get("title")
                })
                seen.add(mitigation)
    
    return recommendations[:10]


def _group_threats_by_control(threats: list) -> dict:
    """Group threats by compliance control"""
    by_control = {}
    
    for threat in threats:
        mappings = threat.get("compliance_mappings", {})
        for framework, controls in mappings.items():
            if framework not in by_control:
                by_control[framework] = {}
            for control in controls:
                if control not in by_control[framework]:
                    by_control[framework][control] = []
                by_control[framework][control].append(threat.get("title"))
    
    return by_control


def _generate_remediation_priority(threats: list) -> list:
    """Generate prioritized remediation list"""
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    sorted_threats = sorted(
        threats,
        key=lambda t: (
            priority_order.get(t.get("severity", "medium").lower(), 2),
            -t.get("overall_risk", 0)
        )
    )
    
    return [
        {
            "priority": i + 1,
            "threat": t.get("title"),
            "severity": t.get("severity"),
            "risk": t.get("overall_risk"),
            "mitigations": t.get("mitigations", [])[:3]
        }
        for i, t in enumerate(sorted_threats[:10])
    ]


async def _format_report_response(report: ReportData, analysis) -> dict:
    """Format report response"""
    return {
        "report_id": report.id,
        "project_id": report.project_id,
        "analysis_id": report.analysis_id,
        "report_type": report.report_type,
        "created_at": report.created_at,
        "format": report.format,
        "has_file": bool(report.file_path),
        "content": report.content
    }
