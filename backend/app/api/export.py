"""
Export API Endpoints
Generate comprehensive security reports in PDF and JSON formats
"""

import io
import json
from typing import Optional
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
import structlog

from app.storage.repository import (
    project_repo,
    analysis_repo,
    report_repo,
)
from app.core.logging import audit_logger

logger = structlog.get_logger()
router = APIRouter()


# ===========================================
# Models
# ===========================================

class ExportRequest(BaseModel):
    """Request model for export"""
    analysis_id: str
    format: str = "json"  # json, pdf
    report_type: str = "full"  # full, executive, technical, compliance
    include_dfd: bool = True
    include_mitigations: bool = True
    include_compliance: bool = True


class ExportResponse(BaseModel):
    """Response metadata for export"""
    export_id: str
    format: str
    report_type: str
    generated_at: str
    file_name: str
    content_type: str


# ===========================================
# Endpoints
# ===========================================

@router.post("/report")
async def export_report(request: ExportRequest):
    """
    Export a comprehensive security report.
    
    Formats:
    - json: Structured JSON data
    - pdf: Formatted PDF document
    
    Report types:
    - full: Complete analysis with all details
    - executive: High-level summary for executives
    - technical: Detailed technical findings
    - compliance: Compliance-focused report
    """
    # Get analysis
    analysis = await analysis_repo.get_analysis(request.analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Get project
    project = await project_repo.get_project(analysis.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Generate report content
    report_data = _build_report_data(
        project=project,
        analysis=analysis,
        report_type=request.report_type,
        include_dfd=request.include_dfd,
        include_mitigations=request.include_mitigations,
        include_compliance=request.include_compliance
    )
    
    # Audit log
    audit_logger.log_data_access(
        user_id="api",
        data_type="export",
        record_id=request.analysis_id,
        action="export",
        format=request.format,
        report_type=request.report_type
    )
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    if request.format == "pdf":
        # Generate PDF
        pdf_buffer = _generate_pdf(report_data, request.report_type)
        
        return StreamingResponse(
            io.BytesIO(pdf_buffer),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=security_report_{timestamp}.pdf"
            }
        )
    else:
        # Return JSON
        return JSONResponse(
            content=report_data,
            headers={
                "Content-Disposition": f"attachment; filename=security_report_{timestamp}.json"
            }
        )


@router.get("/{analysis_id}/json")
async def export_json(analysis_id: str, report_type: str = "full"):
    """Quick JSON export endpoint"""
    analysis = await analysis_repo.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    project = await project_repo.get_project(analysis.project_id)
    
    report_data = _build_report_data(
        project=project,
        analysis=analysis,
        report_type=report_type,
        include_dfd=True,
        include_mitigations=True,
        include_compliance=True
    )
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    return JSONResponse(
        content=report_data,
        headers={
            "Content-Disposition": f"attachment; filename=security_report_{timestamp}.json"
        }
    )


@router.get("/{analysis_id}/pdf")
async def export_pdf(analysis_id: str, report_type: str = "full"):
    """Quick PDF export endpoint"""
    analysis = await analysis_repo.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    project = await project_repo.get_project(analysis.project_id)
    
    report_data = _build_report_data(
        project=project,
        analysis=analysis,
        report_type=report_type,
        include_dfd=True,
        include_mitigations=True,
        include_compliance=True
    )
    
    pdf_buffer = _generate_pdf(report_data, report_type)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    return StreamingResponse(
        io.BytesIO(pdf_buffer),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=security_report_{timestamp}.pdf"
        }
    )


# ===========================================
# Helper Functions
# ===========================================

def _build_report_data(
    project,
    analysis,
    report_type: str,
    include_dfd: bool,
    include_mitigations: bool,
    include_compliance: bool
) -> dict:
    """Build comprehensive report data structure"""
    
    threats = analysis.threats or []
    
    # Calculate statistics
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_risk = 0
    all_mitigations = []
    stride_breakdown = {}
    
    for threat in threats:
        severity = (threat.get("severity") or "medium").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        total_risk += threat.get("overall_risk", 5)
        
        # Collect mitigations
        for m in threat.get("mitigations", []):
            if m not in all_mitigations:
                all_mitigations.append(m)
        
        # STRIDE breakdown
        category = threat.get("category", "Unknown")
        stride_breakdown[category] = stride_breakdown.get(category, 0) + 1
    
    avg_risk = round(total_risk / len(threats), 2) if threats else 0
    
    # Build report structure
    report = {
        "meta": {
            "report_type": report_type,
            "generated_at": datetime.utcnow().isoformat(),
            "generator": "SecurityReview.ai",
            "version": "1.0.0"
        },
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description or "No description provided",
            "created_at": project.created_at
        },
        "analysis": {
            "id": analysis.id,
            "methodology": analysis.methodology,
            "status": analysis.status,
            "created_at": analysis.created_at,
            "completed_at": analysis.completed_at
        },
        "summary": {
            "total_threats": len(threats),
            "severity_breakdown": severity_counts,
            "average_risk_score": avg_risk,
            "critical_and_high": severity_counts["critical"] + severity_counts["high"],
            "stride_breakdown": stride_breakdown,
            "total_mitigations": len(all_mitigations),
            "risk_rating": _calculate_risk_rating(severity_counts, avg_risk)
        }
    }
    
    # Full/Technical reports include all threats
    if report_type in ["full", "technical"]:
        report["threats"] = [
            {
                "id": t.get("id"),
                "title": t.get("title"),
                "description": t.get("description"),
                "category": t.get("category"),
                "stride_category": t.get("stride_category"),
                "severity": t.get("severity"),
                "overall_risk": t.get("overall_risk"),
                "affected_component": t.get("affected_component"),
                "attack_vector": t.get("attack_vector"),
                "dread_score": t.get("dread_score"),
                "mitigations": t.get("mitigations", []) if include_mitigations else [],
                "compliance_mappings": t.get("compliance_mappings", {}) if include_compliance else {},
                "zone": t.get("zone"),
                "trust_boundary": t.get("trust_boundary"),
                "status": t.get("status", "open")
            }
            for t in sorted(threats, key=lambda x: x.get("overall_risk", 0), reverse=True)
        ]
    
    # Executive summary includes top threats only
    elif report_type == "executive":
        top_threats = sorted(threats, key=lambda x: x.get("overall_risk", 0), reverse=True)[:5]
        report["top_threats"] = [
            {
                "title": t.get("title"),
                "severity": t.get("severity"),
                "risk_score": t.get("overall_risk"),
                "business_impact": t.get("business_impact", "Potential security compromise"),
                "recommendation": t.get("mitigations", ["No mitigation defined"])[0] if t.get("mitigations") else "Implement security controls"
            }
            for t in top_threats
        ]
        report["key_recommendations"] = _generate_key_recommendations(threats)
    
    # Compliance report groups by framework
    if include_compliance and report_type in ["full", "compliance"]:
        report["compliance"] = {
            "summary": analysis.compliance_summary or {},
            "frameworks_covered": list((analysis.compliance_summary or {}).keys()),
            "threats_by_control": _group_by_control(threats)
        }
    
    # Include DFD
    if include_dfd and analysis.dfd_mermaid:
        report["data_flow_diagram"] = {
            "mermaid_code": analysis.dfd_mermaid,
            "type": "flowchart"
        }
    
    # Include DevSecOps rules for technical reports
    if report_type == "technical" and analysis.devsecops_rules:
        report["devsecops_rules"] = analysis.devsecops_rules
    
    # Include PASTA stages if used
    if analysis.methodology == "PASTA" and analysis.pasta_stages:
        report["pasta_analysis"] = analysis.pasta_stages
    
    # Remediation roadmap
    if include_mitigations:
        report["remediation_roadmap"] = _generate_remediation_roadmap(threats)
    
    return report


def _calculate_risk_rating(severity_counts: dict, avg_risk: float) -> str:
    """Calculate overall risk rating"""
    if severity_counts["critical"] > 0 or avg_risk >= 8:
        return "Critical"
    if severity_counts["high"] > 2 or avg_risk >= 6:
        return "High"
    if severity_counts["medium"] > 3 or avg_risk >= 4:
        return "Medium"
    return "Low"


def _generate_key_recommendations(threats: list) -> list:
    """Generate key recommendations for executive report"""
    recommendations = []
    priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    
    for threat in sorted(threats, key=lambda x: priority_map.get(x.get("severity", "medium").lower(), 3)):
        for mitigation in threat.get("mitigations", [])[:1]:
            if mitigation not in [r["action"] for r in recommendations]:
                recommendations.append({
                    "priority": threat.get("severity", "medium").upper(),
                    "action": mitigation,
                    "addresses": threat.get("title")
                })
        if len(recommendations) >= 10:
            break
    
    return recommendations


def _group_by_control(threats: list) -> dict:
    """Group threats by compliance control"""
    by_framework = {}
    
    for threat in threats:
        mappings = threat.get("compliance_mappings", {})
        for framework, controls in mappings.items():
            if framework not in by_framework:
                by_framework[framework] = {}
            for control in controls:
                if control not in by_framework[framework]:
                    by_framework[framework][control] = []
                by_framework[framework][control].append({
                    "threat": threat.get("title"),
                    "severity": threat.get("severity")
                })
    
    return by_framework


def _generate_remediation_roadmap(threats: list) -> list:
    """Generate prioritized remediation roadmap"""
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    phases = [
        {"phase": "Immediate (0-30 days)", "items": [], "priority": ["critical"]},
        {"phase": "Short-term (30-90 days)", "items": [], "priority": ["high"]},
        {"phase": "Medium-term (90-180 days)", "items": [], "priority": ["medium"]},
        {"phase": "Long-term (180+ days)", "items": [], "priority": ["low"]}
    ]
    
    for threat in sorted(threats, key=lambda x: priority_order.get(x.get("severity", "medium").lower(), 2)):
        severity = threat.get("severity", "medium").lower()
        phase_idx = priority_order.get(severity, 2)
        
        phases[phase_idx]["items"].append({
            "threat": threat.get("title"),
            "severity": severity,
            "mitigations": threat.get("mitigations", [])[:3],
            "affected_component": threat.get("affected_component")
        })
    
    return [p for p in phases if p["items"]]


def _generate_pdf(report_data: dict, report_type: str) -> bytes:
    """Generate PDF report using HTML template"""
    try:
        # Try using weasyprint for PDF generation
        from weasyprint import HTML, CSS
        
        html_content = _generate_html_report(report_data, report_type)
        
        # Generate PDF
        pdf = HTML(string=html_content).write_pdf(
            stylesheets=[CSS(string=_get_pdf_styles())]
        )
        
        return pdf
        
    except ImportError:
        # Fallback: generate a simple text-based PDF using reportlab
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.75*inch, bottomMargin=0.75*inch)
            
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name='Title', fontSize=24, spaceAfter=30, textColor=colors.HexColor('#6366f1')))
            styles.add(ParagraphStyle(name='Heading1', fontSize=18, spaceAfter=12, spaceBefore=20, textColor=colors.HexColor('#1f2937')))
            styles.add(ParagraphStyle(name='Heading2', fontSize=14, spaceAfter=8, spaceBefore=16, textColor=colors.HexColor('#374151')))
            styles.add(ParagraphStyle(name='Body', fontSize=10, spaceAfter=6, textColor=colors.HexColor('#4b5563')))
            styles.add(ParagraphStyle(name='Small', fontSize=8, textColor=colors.HexColor('#6b7280')))
            
            elements = []
            
            # Title
            elements.append(Paragraph("Security Assessment Report", styles['Title']))
            elements.append(Paragraph(f"Generated: {report_data['meta']['generated_at']}", styles['Small']))
            elements.append(Spacer(1, 20))
            
            # Project Info
            elements.append(Paragraph("Project Information", styles['Heading1']))
            project = report_data['project']
            elements.append(Paragraph(f"<b>Name:</b> {project['name']}", styles['Body']))
            elements.append(Paragraph(f"<b>Description:</b> {project['description']}", styles['Body']))
            elements.append(Paragraph(f"<b>Methodology:</b> {report_data['analysis']['methodology']}", styles['Body']))
            elements.append(Spacer(1, 15))
            
            # Summary
            elements.append(Paragraph("Executive Summary", styles['Heading1']))
            summary = report_data['summary']
            
            summary_data = [
                ['Metric', 'Value'],
                ['Total Threats', str(summary['total_threats'])],
                ['Overall Risk Rating', summary['risk_rating']],
                ['Average Risk Score', str(summary['average_risk_score'])],
                ['Critical', str(summary['severity_breakdown']['critical'])],
                ['High', str(summary['severity_breakdown']['high'])],
                ['Medium', str(summary['severity_breakdown']['medium'])],
                ['Low', str(summary['severity_breakdown']['low'])],
            ]
            
            table = Table(summary_data, colWidths=[3*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9fafb')),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))
            
            # Threats
            if 'threats' in report_data:
                elements.append(PageBreak())
                elements.append(Paragraph("Identified Threats", styles['Heading1']))
                
                for i, threat in enumerate(report_data['threats'][:20], 1):  # Limit to 20
                    severity_colors = {
                        'critical': '#ef4444',
                        'high': '#f97316',
                        'medium': '#eab308',
                        'low': '#22c55e'
                    }
                    sev = threat.get('severity', 'medium').lower()
                    sev_color = severity_colors.get(sev, '#6b7280')
                    
                    elements.append(Paragraph(
                        f"<b>{i}. {threat['title']}</b> "
                        f"<font color='{sev_color}'>[{threat.get('severity', 'Medium').upper()}]</font> "
                        f"<font color='#6b7280'>Risk: {threat.get('overall_risk', 'N/A')}</font>",
                        styles['Heading2']
                    ))
                    elements.append(Paragraph(f"{threat.get('description', 'No description')}", styles['Body']))
                    elements.append(Paragraph(f"<b>Affected:</b> {threat.get('affected_component', 'N/A')}", styles['Body']))
                    
                    if threat.get('mitigations'):
                        elements.append(Paragraph("<b>Mitigations:</b>", styles['Body']))
                        for m in threat['mitigations'][:3]:
                            elements.append(Paragraph(f"  • {m}", styles['Body']))
                    
                    elements.append(Spacer(1, 10))
            
            # Top threats for executive
            elif 'top_threats' in report_data:
                elements.append(Paragraph("Top Priority Threats", styles['Heading1']))
                for i, threat in enumerate(report_data['top_threats'], 1):
                    elements.append(Paragraph(
                        f"<b>{i}. {threat['title']}</b> [{threat['severity'].upper()}]",
                        styles['Heading2']
                    ))
                    elements.append(Paragraph(f"<b>Business Impact:</b> {threat['business_impact']}", styles['Body']))
                    elements.append(Paragraph(f"<b>Recommendation:</b> {threat['recommendation']}", styles['Body']))
                    elements.append(Spacer(1, 10))
            
            # Remediation Roadmap
            if 'remediation_roadmap' in report_data:
                elements.append(PageBreak())
                elements.append(Paragraph("Remediation Roadmap", styles['Heading1']))
                
                for phase in report_data['remediation_roadmap']:
                    elements.append(Paragraph(f"<b>{phase['phase']}</b>", styles['Heading2']))
                    for item in phase['items'][:5]:
                        elements.append(Paragraph(f"• {item['threat']} ({item['severity'].upper()})", styles['Body']))
                    elements.append(Spacer(1, 10))
            
            # Data Flow Diagram code
            if 'data_flow_diagram' in report_data:
                elements.append(PageBreak())
                elements.append(Paragraph("Data Flow Diagram (Mermaid)", styles['Heading1']))
                elements.append(Paragraph("The following Mermaid code can be rendered using any Mermaid viewer:", styles['Body']))
                elements.append(Spacer(1, 10))
                
                dfd_code = report_data['data_flow_diagram']['mermaid_code']
                # Truncate if too long
                if len(dfd_code) > 2000:
                    dfd_code = dfd_code[:2000] + "\n... (truncated)"
                
                for line in dfd_code.split('\n')[:30]:
                    elements.append(Paragraph(f"<font face='Courier' size='8'>{line}</font>", styles['Body']))
            
            # Build PDF
            doc.build(elements)
            
            return buffer.getvalue()
            
        except ImportError:
            # If no PDF library available, return JSON with note
            logger.warning("No PDF library available, returning JSON instead")
            return json.dumps({
                "error": "PDF generation not available",
                "note": "Install 'weasyprint' or 'reportlab' for PDF export",
                "data": report_data
            }, indent=2).encode('utf-8')


def _generate_html_report(report_data: dict, report_type: str) -> str:
    """Generate HTML for PDF conversion"""
    
    project = report_data['project']
    summary = report_data['summary']
    analysis = report_data['analysis']
    
    # Severity badge colors
    severity_colors = {
        'critical': '#ef4444',
        'high': '#f97316', 
        'medium': '#eab308',
        'low': '#22c55e'
    }
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Security Assessment Report - {project['name']}</title>
    </head>
    <body>
        <header>
            <h1>🛡️ Security Assessment Report</h1>
            <p class="subtitle">{project['name']}</p>
            <p class="meta">Generated: {report_data['meta']['generated_at']} | Methodology: {analysis['methodology']}</p>
        </header>
        
        <section class="summary">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{summary['total_threats']}</div>
                    <div class="stat-label">Total Threats</div>
                </div>
                <div class="stat-card risk-{summary['risk_rating'].lower()}">
                    <div class="stat-value">{summary['risk_rating']}</div>
                    <div class="stat-label">Risk Rating</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{summary['average_risk_score']}</div>
                    <div class="stat-label">Avg Risk Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{summary['critical_and_high']}</div>
                    <div class="stat-label">Critical + High</div>
                </div>
            </div>
            
            <h3>Severity Breakdown</h3>
            <table class="severity-table">
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr class="critical"><td>Critical</td><td>{summary['severity_breakdown']['critical']}</td></tr>
                <tr class="high"><td>High</td><td>{summary['severity_breakdown']['high']}</td></tr>
                <tr class="medium"><td>Medium</td><td>{summary['severity_breakdown']['medium']}</td></tr>
                <tr class="low"><td>Low</td><td>{summary['severity_breakdown']['low']}</td></tr>
            </table>
        </section>
    """
    
    # Add threats section
    if 'threats' in report_data:
        html += """
        <section class="threats">
            <h2>Identified Threats</h2>
        """
        for i, threat in enumerate(report_data['threats'], 1):
            sev = threat.get('severity', 'medium').lower()
            sev_color = severity_colors.get(sev, '#6b7280')
            
            html += f"""
            <div class="threat-card">
                <div class="threat-header">
                    <span class="threat-number">{i}</span>
                    <h3>{threat['title']}</h3>
                    <span class="severity-badge" style="background: {sev_color}">{threat.get('severity', 'Medium').upper()}</span>
                    <span class="risk-score">Risk: {threat.get('overall_risk', 'N/A')}</span>
                </div>
                <p class="threat-desc">{threat.get('description', 'No description')}</p>
                <p><strong>Affected Component:</strong> {threat.get('affected_component', 'N/A')}</p>
                <p><strong>Category:</strong> {threat.get('category', 'N/A')}</p>
            """
            
            if threat.get('mitigations'):
                html += "<div class='mitigations'><strong>Mitigations:</strong><ul>"
                for m in threat['mitigations']:
                    html += f"<li>{m}</li>"
                html += "</ul></div>"
            
            html += "</div>"
        
        html += "</section>"
    
    # Add top threats for executive
    elif 'top_threats' in report_data:
        html += """
        <section class="top-threats">
            <h2>Top Priority Threats</h2>
        """
        for i, threat in enumerate(report_data['top_threats'], 1):
            html += f"""
            <div class="threat-card">
                <div class="threat-header">
                    <span class="threat-number">{i}</span>
                    <h3>{threat['title']}</h3>
                    <span class="severity-badge">{threat['severity'].upper()}</span>
                </div>
                <p><strong>Business Impact:</strong> {threat['business_impact']}</p>
                <p><strong>Recommendation:</strong> {threat['recommendation']}</p>
            </div>
            """
        html += "</section>"
    
    # Add remediation roadmap
    if 'remediation_roadmap' in report_data:
        html += """
        <section class="roadmap">
            <h2>Remediation Roadmap</h2>
        """
        for phase in report_data['remediation_roadmap']:
            html += f"""
            <div class="phase">
                <h3>{phase['phase']}</h3>
                <ul>
            """
            for item in phase['items']:
                html += f"<li><strong>{item['threat']}</strong> ({item['severity'].upper()})</li>"
            html += "</ul></div>"
        html += "</section>"
    
    # Add DFD
    if 'data_flow_diagram' in report_data:
        html += f"""
        <section class="dfd">
            <h2>Data Flow Diagram</h2>
            <p class="dfd-note">Mermaid code (render using mermaid.live or similar):</p>
            <pre><code>{report_data['data_flow_diagram']['mermaid_code']}</code></pre>
        </section>
        """
    
    html += """
        <footer>
            <p>Generated by SecurityReview.ai | Confidential</p>
        </footer>
    </body>
    </html>
    """
    
    return html


def _get_pdf_styles() -> str:
    """Get CSS styles for PDF"""
    return """
    @page {
        size: A4;
        margin: 2cm;
    }
    
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 11pt;
        line-height: 1.5;
        color: #1f2937;
    }
    
    header {
        text-align: center;
        border-bottom: 3px solid #6366f1;
        padding-bottom: 20px;
        margin-bottom: 30px;
    }
    
    h1 {
        color: #6366f1;
        font-size: 28pt;
        margin-bottom: 5px;
    }
    
    .subtitle {
        font-size: 18pt;
        color: #374151;
        margin: 5px 0;
    }
    
    .meta {
        font-size: 10pt;
        color: #6b7280;
    }
    
    h2 {
        color: #1f2937;
        font-size: 16pt;
        border-bottom: 2px solid #e5e7eb;
        padding-bottom: 8px;
        margin-top: 30px;
    }
    
    h3 {
        color: #374151;
        font-size: 12pt;
        margin-top: 20px;
    }
    
    .stats-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 15px;
        margin: 20px 0;
    }
    
    .stat-card {
        background: #f3f4f6;
        border-radius: 8px;
        padding: 15px 25px;
        text-align: center;
        flex: 1;
        min-width: 100px;
    }
    
    .stat-value {
        font-size: 24pt;
        font-weight: bold;
        color: #6366f1;
    }
    
    .stat-label {
        font-size: 9pt;
        color: #6b7280;
        text-transform: uppercase;
    }
    
    .risk-critical .stat-value { color: #ef4444; }
    .risk-high .stat-value { color: #f97316; }
    .risk-medium .stat-value { color: #eab308; }
    .risk-low .stat-value { color: #22c55e; }
    
    .severity-table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
    }
    
    .severity-table th, .severity-table td {
        padding: 10px;
        text-align: left;
        border: 1px solid #e5e7eb;
    }
    
    .severity-table th {
        background: #6366f1;
        color: white;
    }
    
    .severity-table tr.critical td:first-child { border-left: 4px solid #ef4444; }
    .severity-table tr.high td:first-child { border-left: 4px solid #f97316; }
    .severity-table tr.medium td:first-child { border-left: 4px solid #eab308; }
    .severity-table tr.low td:first-child { border-left: 4px solid #22c55e; }
    
    .threat-card {
        background: #f9fafb;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 15px;
        margin: 15px 0;
        page-break-inside: avoid;
    }
    
    .threat-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 10px;
    }
    
    .threat-number {
        background: #6366f1;
        color: white;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 10pt;
        font-weight: bold;
    }
    
    .threat-header h3 {
        flex: 1;
        margin: 0;
    }
    
    .severity-badge {
        color: white;
        padding: 3px 10px;
        border-radius: 4px;
        font-size: 9pt;
        font-weight: bold;
    }
    
    .risk-score {
        color: #6b7280;
        font-size: 10pt;
    }
    
    .threat-desc {
        color: #4b5563;
        margin: 10px 0;
    }
    
    .mitigations {
        background: #ecfdf5;
        border-left: 4px solid #22c55e;
        padding: 10px;
        margin-top: 10px;
    }
    
    .mitigations ul {
        margin: 5px 0;
        padding-left: 20px;
    }
    
    .mitigations li {
        margin: 3px 0;
    }
    
    .phase {
        margin: 15px 0;
        padding: 15px;
        background: #f9fafb;
        border-radius: 8px;
    }
    
    .dfd {
        margin-top: 30px;
    }
    
    .dfd-note {
        font-style: italic;
        color: #6b7280;
    }
    
    pre {
        background: #1f2937;
        color: #e5e7eb;
        padding: 15px;
        border-radius: 8px;
        font-size: 9pt;
        overflow-x: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    
    footer {
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1px solid #e5e7eb;
        text-align: center;
        font-size: 9pt;
        color: #6b7280;
    }
    """

