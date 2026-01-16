"""
Threats API - CRUD operations for threat model artifacts
"""

from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from app.storage.repository import analysis_repo, threat_repo, project_repo
from app.core.logging import audit_logger

logger = structlog.get_logger()
router = APIRouter()


# ===========================================
# Models
# ===========================================

class ThreatUpdate(BaseModel):
    """Update a threat"""
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    affected_component: Optional[str] = None
    attack_vector: Optional[str] = None
    mitigations: Optional[List[str]] = None
    dread_score: Optional[Dict[str, float]] = None
    zone: Optional[str] = None
    trust_boundary: Optional[str] = None
    stride_category: Optional[str] = None
    status: Optional[str] = None  # identified, mitigated, accepted, transferred


class ThreatCreate(BaseModel):
    """Create a new threat"""
    analysis_id: str
    title: str
    description: str
    category: str = "Information Disclosure"
    severity: str = "medium"
    affected_component: str = ""
    attack_vector: str = ""
    mitigations: List[str] = Field(default_factory=list)
    dread_score: Dict[str, float] = Field(default_factory=lambda: {"damage": 5, "reproducibility": 5, "exploitability": 5, "affected_users": 5, "discoverability": 5})
    zone: Optional[str] = None
    trust_boundary: Optional[str] = None
    stride_category: str = "I"
    status: str = "identified"


class MitigationUpdate(BaseModel):
    """Update mitigations for a threat"""
    mitigations: List[str]
    status: Optional[str] = None


class DiagramUpdate(BaseModel):
    """Update diagram"""
    mermaid_code: str
    zones: Optional[List[Dict[str, Any]]] = None
    trust_boundaries: Optional[List[Dict[str, Any]]] = None
    components: Optional[List[Dict[str, Any]]] = None
    data_flows: Optional[List[Dict[str, Any]]] = None


class ZoneCreate(BaseModel):
    """Create/update a zone"""
    id: str
    name: str
    description: Optional[str] = ""
    color: Optional[str] = "#fef3c7"
    components: List[str] = Field(default_factory=list)


class TrustBoundaryCreate(BaseModel):
    """Create/update a trust boundary"""
    id: str
    name: str
    zones: List[str] = Field(default_factory=list)
    style: Optional[str] = "dashed"
    color: Optional[str] = "#ef4444"


# ===========================================
# Threat CRUD
# ===========================================

@router.get("/{analysis_id}")
async def list_threats(analysis_id: str):
    """List all threats for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    threats = await threat_repo.for_analysis(analysis_id)
    return {"analysis_id": analysis_id, "threats": threats or analysis.threats, "count": len(threats or analysis.threats)}


@router.post("")
async def create_threat(threat: ThreatCreate):
    """Create a new threat"""
    import uuid
    
    analysis = await analysis_repo.get(threat.analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    threat_id = str(uuid.uuid4())
    threat_data = {
        "id": threat_id,
        **threat.model_dump(),
        "overall_risk": sum(threat.dread_score.values()) / 5,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "compliance_mappings": {}
    }
    
    # Save to threat repo
    await threat_repo.save(threat_id, threat_data)
    
    # Update analysis
    analysis.threats.append(threat_data)
    await analysis_repo.save(analysis.id, {
        **analysis.__dict__,
        "threats": analysis.threats
    })
    
    audit_logger.log_data_access("api", "threat", threat_id, action="create")
    logger.info("threat_created", id=threat_id, analysis_id=threat.analysis_id)
    
    return {"id": threat_id, "status": "created", "threat": threat_data}


@router.put("/{threat_id}")
async def update_threat(threat_id: str, update: ThreatUpdate):
    """Update a threat"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    # Apply updates
    updates = {k: v for k, v in update.model_dump().items() if v is not None}
    threat.update(updates)
    threat["updated_at"] = datetime.utcnow().isoformat()
    
    # Recalculate risk if DREAD scores changed
    if "dread_score" in updates:
        threat["overall_risk"] = sum(threat["dread_score"].values()) / 5
    
    await threat_repo.save(threat_id, threat)
    
    # Update in analysis too
    analysis_id = threat.get("analysis_id")
    if analysis_id:
        analysis = await analysis_repo.get(analysis_id)
        if analysis:
            analysis.threats = [t if t.get("id") != threat_id else threat for t in analysis.threats]
            await analysis_repo.save(analysis_id, analysis.__dict__)
    
    audit_logger.log_data_access("api", "threat", threat_id, action="update")
    
    return {"id": threat_id, "status": "updated", "threat": threat}


@router.delete("/{threat_id}")
async def delete_threat(threat_id: str):
    """Delete a threat"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    analysis_id = threat.get("analysis_id")
    
    # Remove from threat repo
    await threat_repo.delete(threat_id)
    
    # Remove from analysis
    if analysis_id:
        analysis = await analysis_repo.get(analysis_id)
        if analysis:
            analysis.threats = [t for t in analysis.threats if t.get("id") != threat_id]
            await analysis_repo.save(analysis_id, analysis.__dict__)
    
    audit_logger.log_data_access("api", "threat", threat_id, action="delete")
    
    return {"id": threat_id, "status": "deleted"}


@router.put("/{threat_id}/mitigations")
async def update_mitigations(threat_id: str, update: MitigationUpdate):
    """Update mitigations for a threat"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    threat["mitigations"] = update.mitigations
    if update.status:
        threat["status"] = update.status
    threat["updated_at"] = datetime.utcnow().isoformat()
    
    await threat_repo.save(threat_id, threat)
    
    return {"id": threat_id, "mitigations": update.mitigations, "status": threat.get("status")}


# ===========================================
# Diagram Management
# ===========================================

@router.get("/{analysis_id}/diagram")
async def get_diagram(analysis_id: str):
    """Get diagram data for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    return {
        "analysis_id": analysis_id,
        "mermaid_code": analysis.dfd_mermaid,
        "metadata": analysis.metadata.get("diagram", {})
    }


@router.put("/{analysis_id}/diagram")
async def update_diagram(analysis_id: str, update: DiagramUpdate):
    """Update diagram for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    # Update diagram
    diagram_metadata = {
        "zones": update.zones or [],
        "trust_boundaries": update.trust_boundaries or [],
        "components": update.components or [],
        "data_flows": update.data_flows or [],
        "updated_at": datetime.utcnow().isoformat()
    }
    
    await analysis_repo.update(
        analysis_id,
        dfd_mermaid=update.mermaid_code,
        metadata={**analysis.metadata, "diagram": diagram_metadata}
    )
    
    audit_logger.log_data_access("api", "diagram", analysis_id, action="update")
    
    return {"analysis_id": analysis_id, "status": "updated", "mermaid_code": update.mermaid_code}


# ===========================================
# Zones & Trust Boundaries
# ===========================================

@router.post("/{analysis_id}/zones")
async def add_zone(analysis_id: str, zone: ZoneCreate):
    """Add or update a zone"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    diagram_meta = analysis.metadata.get("diagram", {"zones": []})
    zones = diagram_meta.get("zones", [])
    
    # Update or add
    existing = next((i for i, z in enumerate(zones) if z["id"] == zone.id), None)
    zone_data = zone.model_dump()
    
    if existing is not None:
        zones[existing] = zone_data
    else:
        zones.append(zone_data)
    
    diagram_meta["zones"] = zones
    await analysis_repo.update(analysis_id, metadata={**analysis.metadata, "diagram": diagram_meta})
    
    return {"zone": zone_data, "status": "saved"}


@router.post("/{analysis_id}/trust-boundaries")
async def add_trust_boundary(analysis_id: str, boundary: TrustBoundaryCreate):
    """Add or update a trust boundary"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    diagram_meta = analysis.metadata.get("diagram", {"trust_boundaries": []})
    boundaries = diagram_meta.get("trust_boundaries", [])
    
    existing = next((i for i, b in enumerate(boundaries) if b["id"] == boundary.id), None)
    boundary_data = boundary.model_dump()
    
    if existing is not None:
        boundaries[existing] = boundary_data
    else:
        boundaries.append(boundary_data)
    
    diagram_meta["trust_boundaries"] = boundaries
    await analysis_repo.update(analysis_id, metadata={**analysis.metadata, "diagram": diagram_meta})
    
    return {"trust_boundary": boundary_data, "status": "saved"}


@router.get("/{analysis_id}/export")
async def export_threat_model(analysis_id: str, format: str = "json"):
    """Export complete threat model"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    project = await project_repo.get(analysis.project_id)
    
    export_data = {
        "version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
        "project": {"id": project.id, "name": project.name} if project else {},
        "analysis": {
            "id": analysis.id,
            "methodology": analysis.methodology,
            "status": analysis.status,
            "created_at": analysis.created_at
        },
        "diagram": {
            "mermaid": analysis.dfd_mermaid,
            **analysis.metadata.get("diagram", {})
        },
        "threats": analysis.threats,
        "compliance": analysis.compliance_summary,
        "summary": analysis.summary
    }
    
    return export_data


