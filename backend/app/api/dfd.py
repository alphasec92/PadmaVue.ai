"""
Data Flow Diagram (DFD) API Endpoints
Generates and serves Mermaid.js diagrams
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from app.generators.mermaid import MermaidGenerator
from app.api.ingest import ingestion_store
from app.api.analyze import analysis_store

logger = structlog.get_logger()
router = APIRouter()


class DFDComponent(BaseModel):
    """Model for a DFD component"""
    id: str
    name: str
    type: str  # external_entity, process, data_store, trust_boundary
    description: Optional[str] = None
    trust_level: Optional[str] = None


class DFDFlow(BaseModel):
    """Model for a data flow"""
    id: str
    source: str
    target: str
    label: str
    data_type: Optional[str] = None
    protocol: Optional[str] = None
    encrypted: bool = False


class DFDRequest(BaseModel):
    """Request model for DFD generation"""
    project_id: str
    diagram_type: str = Field(default="flowchart", description="Type: flowchart, sequence, class")
    include_trust_boundaries: bool = Field(default=True)
    include_data_flows: bool = Field(default=True)
    highlight_threats: bool = Field(default=True)
    style: str = Field(default="default", description="Style: default, dark, colorful")


class DFDResponse(BaseModel):
    """Response model for DFD"""
    project_id: str
    diagram_type: str
    mermaid_code: str
    components: List[DFDComponent]
    flows: List[DFDFlow]
    generated_at: str
    metadata: Dict[str, Any]


@router.get("/{project_id}")
async def get_dfd(
    project_id: str,
    diagram_type: str = "flowchart",
    include_trust_boundaries: bool = True,
    highlight_threats: bool = True,
    style: str = "default"
) -> DFDResponse:
    """
    Get Data Flow Diagram for a project.
    
    Returns Mermaid.js code that can be rendered in the frontend.
    """
    # Check if project exists
    if project_id not in ingestion_store:
        raise HTTPException(status_code=404, detail="Project not found")
    
    logger.info("Generating DFD",
               project_id=project_id,
               diagram_type=diagram_type)
    
    try:
        # Initialize generator
        generator = MermaidGenerator()
        
        # Get project data
        project_data = ingestion_store[project_id]
        
        # Check for existing analysis
        project_analysis = None
        for analysis in analysis_store.values():
            if analysis.get("project_id") == project_id:
                project_analysis = analysis
                break
        
        # Generate DFD
        result = await generator.generate_dfd(
            project_data=project_data,
            analysis_data=project_analysis,
            diagram_type=diagram_type,
            include_trust_boundaries=include_trust_boundaries,
            highlight_threats=highlight_threats,
            style=style
        )
        
        return DFDResponse(
            project_id=project_id,
            diagram_type=diagram_type,
            mermaid_code=result["mermaid_code"],
            components=result.get("components", []),
            flows=result.get("flows", []),
            generated_at=datetime.utcnow().isoformat(),
            metadata=result.get("metadata", {})
        )
        
    except Exception as e:
        logger.error("DFD generation failed", error=str(e), project_id=project_id)
        raise HTTPException(status_code=500, detail=f"DFD generation failed: {str(e)}")


@router.post("")
async def generate_dfd(request: DFDRequest) -> DFDResponse:
    """
    Generate a new Data Flow Diagram with custom parameters.
    """
    return await get_dfd(
        project_id=request.project_id,
        diagram_type=request.diagram_type,
        include_trust_boundaries=request.include_trust_boundaries,
        highlight_threats=request.highlight_threats,
        style=request.style
    )


@router.get("/{project_id}/components")
async def get_dfd_components(project_id: str) -> Dict[str, Any]:
    """
    Get individual DFD components for a project.
    Useful for building custom diagrams.
    """
    if project_id not in ingestion_store:
        raise HTTPException(status_code=404, detail="Project not found")
    
    generator = MermaidGenerator()
    project_data = ingestion_store[project_id]
    
    components = await generator.extract_components(project_data)
    
    return {
        "project_id": project_id,
        "components": components,
        "total": len(components)
    }


@router.get("/{project_id}/flows")
async def get_data_flows(project_id: str) -> Dict[str, Any]:
    """
    Get data flows for a project.
    """
    if project_id not in ingestion_store:
        raise HTTPException(status_code=404, detail="Project not found")
    
    generator = MermaidGenerator()
    project_data = ingestion_store[project_id]
    
    flows = await generator.extract_flows(project_data)
    
    return {
        "project_id": project_id,
        "flows": flows,
        "total": len(flows)
    }


@router.get("/{project_id}/export/{format}")
async def export_dfd(
    project_id: str,
    format: str = "mermaid"
) -> Dict[str, Any]:
    """
    Export DFD in various formats.
    
    Supported formats: mermaid, json, svg (requires external rendering)
    """
    if project_id not in ingestion_store:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if format not in ["mermaid", "json"]:
        raise HTTPException(status_code=400, detail="Unsupported format. Use: mermaid, json")
    
    dfd_response = await get_dfd(project_id)
    
    if format == "mermaid":
        return {
            "format": "mermaid",
            "content": dfd_response.mermaid_code,
            "content_type": "text/plain"
        }
    
    elif format == "json":
        return {
            "format": "json",
            "content": {
                "components": [c.model_dump() for c in dfd_response.components],
                "flows": [f.model_dump() for f in dfd_response.flows],
                "metadata": dfd_response.metadata
            },
            "content_type": "application/json"
        }


