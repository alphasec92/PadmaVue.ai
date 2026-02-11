"""
Threats API - CRUD operations for threat model artifacts
Enhanced with structured mitigations, attack scenarios, and flow map linking
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
import structlog

from app.storage.repository import analysis_repo, threat_repo, project_repo
from app.core.logging import audit_logger
from app.engines.dread import DREADEngine
from app.models.threat import (
    MitigationType,
    MitigationStatus,
    ConfidenceLevel,
    StructuredMitigation,
    ThreatEnhanced,
    FlowMapComponent,
    FlowMapFlow,
    FlowMapData,
    migrate_legacy_threat,
    infer_mitigation_type,
    generate_scoring_explanation,
)

logger = structlog.get_logger()
router = APIRouter()
dread_engine = DREADEngine()


# ===========================================
# Request/Response Models
# ===========================================

class ThreatUpdateRequest(BaseModel):
    """Update a threat - all fields optional"""
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
    status: Optional[str] = None
    
    # Enhanced fields
    affected_component_ids: Optional[List[str]] = None
    impacted_flow_ids: Optional[List[str]] = None
    trust_boundaries: Optional[List[str]] = None
    assets_impacted: Optional[List[str]] = None
    preconditions: Optional[List[str]] = None
    attack_scenario_steps: Optional[List[str]] = None
    impact_narrative: Optional[str] = None
    confidence: Optional[ConfidenceLevel] = None
    structured_mitigations: Optional[List[Dict[str, Any]]] = None


class ThreatCreateRequest(BaseModel):
    """Create a new threat"""
    analysis_id: str
    title: str
    description: str
    category: str = "Information Disclosure"
    severity: str = "medium"
    affected_component: str = ""
    attack_vector: str = ""
    mitigations: List[str] = Field(default_factory=list)
    dread_score: Dict[str, float] = Field(
        default_factory=lambda: {
            "damage": 5, "reproducibility": 5, "exploitability": 5,
            "affected_users": 5, "discoverability": 5
        }
    )
    zone: Optional[str] = None
    trust_boundary: Optional[str] = None
    stride_category: str = "I"
    status: str = "identified"
    
    # Enhanced fields
    affected_component_ids: List[str] = Field(default_factory=list)
    impacted_flow_ids: List[str] = Field(default_factory=list)
    trust_boundaries: List[str] = Field(default_factory=list)
    assets_impacted: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    attack_scenario_steps: List[str] = Field(default_factory=list)
    impact_narrative: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    structured_mitigations: List[Dict[str, Any]] = Field(default_factory=list)


class MitigationUpdateRequest(BaseModel):
    """Update mitigations for a threat - legacy support"""
    mitigations: List[str]
    status: Optional[str] = None


class StructuredMitigationRequest(BaseModel):
    """Create/update a structured mitigation"""
    text: str
    mitigation_type: MitigationType = MitigationType.PREVENT
    status: MitigationStatus = MitigationStatus.PLANNED
    owner: Optional[str] = None
    verification: List[str] = Field(default_factory=list)


class DiagramUpdateRequest(BaseModel):
    """Update diagram"""
    mermaid_code: str
    zones: Optional[List[Dict[str, Any]]] = None
    trust_boundaries: Optional[List[Dict[str, Any]]] = None
    components: Optional[List[Dict[str, Any]]] = None
    data_flows: Optional[List[Dict[str, Any]]] = None


class ZoneCreateRequest(BaseModel):
    """Create/update a zone"""
    id: str
    name: str
    description: Optional[str] = ""
    color: Optional[str] = "#fef3c7"
    components: List[str] = Field(default_factory=list)


class TrustBoundaryCreateRequest(BaseModel):
    """Create/update a trust boundary"""
    id: str
    name: str
    zones: List[str] = Field(default_factory=list)
    style: Optional[str] = "dashed"
    color: Optional[str] = "#ef4444"


# ===========================================
# Helper Functions
# ===========================================

def enrich_threat_data(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich threat data with computed fields and migration"""
    # Migrate legacy format
    enriched = migrate_legacy_threat(threat_data)
    
    # Ensure overall_risk is calculated from dread_score
    if "dread_score" in enriched:
        dread = enriched["dread_score"]
        if isinstance(dread, dict):
            enriched["overall_risk"] = sum(dread.values()) / 5
            
            # Generate scoring explanation if missing
            if not enriched.get("scoring_explanation"):
                enriched["scoring_explanation"] = generate_scoring_explanation(
                    dread, enriched["overall_risk"]
                )
    
    return enriched


async def get_flow_map_for_analysis(analysis_id: str) -> FlowMapData:
    """Get flow map components and flows for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        return FlowMapData()
    
    diagram_meta = analysis.metadata.get("diagram", {})
    
    # Extract components
    raw_components = diagram_meta.get("components", [])
    components = [
        FlowMapComponent(
            id=c.get("id", ""),
            name=c.get("name", ""),
            type=c.get("type", "process"),
            trust_boundary=c.get("trust_boundary"),
            description=c.get("description"),
            layer=c.get("layer"),
        )
        for c in raw_components if c.get("id")
    ]
    
    # Extract flows
    raw_flows = diagram_meta.get("data_flows", [])
    flows = [
        FlowMapFlow(
            id=f.get("id", ""),
            name=f.get("label", f.get("name", "")),
            source=f.get("source", f.get("source_id", "")),
            target=f.get("target", f.get("target_id", "")),
            protocol=f.get("protocol"),
            auth=f.get("auth"),
            data_classification=f.get("data_classification", f.get("data_type")),
            crosses_trust_boundary=f.get("crosses_trust_boundary", False),
            encrypted=f.get("encrypted", False),
        )
        for f in raw_flows if f.get("id")
    ]
    
    trust_boundaries = diagram_meta.get("trust_boundaries", [])
    
    return FlowMapData(
        components=components,
        flows=flows,
        trust_boundaries=trust_boundaries
    )


# ===========================================
# Threat CRUD Endpoints
# ===========================================

@router.get("/{analysis_id}")
async def list_threats(
    analysis_id: str,
    include_flows: bool = Query(False, description="Include flow map data")
):
    """List all threats for an analysis with enhanced data"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    # Get threats from repo or analysis
    threats = await threat_repo.for_analysis(analysis_id)
    if not threats:
        threats = analysis.threats or []
    
    # Enrich all threats
    enriched_threats = [enrich_threat_data(t) for t in threats]
    
    response = {
        "analysis_id": analysis_id,
        "threats": enriched_threats,
        "count": len(enriched_threats)
    }
    
    # Optionally include flow map data
    if include_flows:
        flow_map = await get_flow_map_for_analysis(analysis_id)
        response["flow_map"] = {
            "components": [c.model_dump() for c in flow_map.components],
            "flows": [f.model_dump(by_alias=True) for f in flow_map.flows],
            "trust_boundaries": flow_map.trust_boundaries
        }
    
    return response


@router.get("/{analysis_id}/threat/{threat_id}")
async def get_threat_detail(
    analysis_id: str,
    threat_id: str,
    include_flows: bool = Query(True, description="Include related flows/components")
):
    """Get full threat detail with related flow map data"""
    # Load threat
    threat = await threat_repo.load(threat_id)
    if not threat:
        # Try to find in analysis
        analysis = await analysis_repo.get(analysis_id)
        if analysis:
            threat = next((t for t in analysis.threats if t.get("id") == threat_id), None)
    
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    # Enrich threat
    enriched = enrich_threat_data(threat)
    
    response = {"threat": enriched}
    
    # Include related components and flows
    if include_flows:
        flow_map = await get_flow_map_for_analysis(analysis_id)
        
        # Filter to related components/flows
        affected_ids = set(enriched.get("affected_component_ids", []))
        flow_ids = set(enriched.get("impacted_flow_ids", []))
        
        related_components = [
            c.model_dump() for c in flow_map.components
            if c.id in affected_ids
        ]
        related_flows = [
            f.model_dump(by_alias=True) for f in flow_map.flows
            if f.id in flow_ids
        ]
        
        response["components"] = related_components
        response["flows"] = related_flows
    
    return response


@router.post("")
async def create_threat(request: ThreatCreateRequest):
    """Create a new threat with enhanced fields"""
    analysis = await analysis_repo.get(request.analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    threat_id = str(uuid.uuid4())
    
    # Calculate risk with explanation
    dread_result = dread_engine.calculate_from_dict_with_explanation(request.dread_score)
    
    # Convert structured mitigations or create from legacy
    structured_mits = request.structured_mitigations
    if not structured_mits and request.mitigations:
        structured_mits = [
            StructuredMitigation.from_legacy_string(m).model_dump()
            for m in request.mitigations
        ]
    
    threat_data = {
        "id": threat_id,
        **request.model_dump(),
        "overall_risk": dread_result["score"],
        "scoring_model": dread_result["scoring_model"],
        "scoring_explanation": dread_result["scoring_explanation"],
        "structured_mitigations": structured_mits,
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
    logger.info("threat_created", id=threat_id, analysis_id=request.analysis_id)
    
    return {"id": threat_id, "status": "created", "threat": threat_data}


@router.put("/{threat_id}")
async def update_threat(threat_id: str, request: ThreatUpdateRequest):
    """Update a threat with enhanced fields"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    # Apply updates (only non-None values)
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    threat.update(updates)
    threat["updated_at"] = datetime.utcnow().isoformat()
    
    # Recalculate risk if DREAD scores changed
    if "dread_score" in updates:
        dread_result = dread_engine.calculate_from_dict_with_explanation(threat["dread_score"])
        threat["overall_risk"] = dread_result["score"]
        threat["scoring_model"] = dread_result["scoring_model"]
        threat["scoring_explanation"] = dread_result["scoring_explanation"]
    
    await threat_repo.save(threat_id, threat)
    
    # Update in analysis too
    analysis_id = threat.get("analysis_id")
    if analysis_id:
        analysis = await analysis_repo.get(analysis_id)
        if analysis:
            analysis.threats = [
                t if t.get("id") != threat_id else threat
                for t in analysis.threats
            ]
            await analysis_repo.save(analysis_id, analysis.__dict__)
    
    audit_logger.log_data_access("api", "threat", threat_id, action="update")
    
    return {"id": threat_id, "status": "updated", "threat": threat}


@router.patch("/{threat_id}")
async def patch_threat(threat_id: str, request: ThreatUpdateRequest):
    """Patch a threat (alias for PUT for REST compatibility)"""
    return await update_threat(threat_id, request)


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


# ===========================================
# Mitigation Management
# ===========================================

@router.put("/{threat_id}/mitigations")
async def update_mitigations_legacy(threat_id: str, request: MitigationUpdateRequest):
    """Update mitigations for a threat (legacy string format)"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    # Update legacy mitigations
    threat["mitigations"] = request.mitigations
    
    # Also update structured mitigations
    threat["structured_mitigations"] = [
        StructuredMitigation.from_legacy_string(m).model_dump()
        for m in request.mitigations
    ]
    
    if request.status:
        threat["status"] = request.status
    threat["updated_at"] = datetime.utcnow().isoformat()
    
    await threat_repo.save(threat_id, threat)
    
    return {
        "id": threat_id,
        "mitigations": request.mitigations,
        "structured_mitigations": threat["structured_mitigations"],
        "status": threat.get("status")
    }


@router.post("/{threat_id}/mitigations")
async def add_structured_mitigation(threat_id: str, request: StructuredMitigationRequest):
    """Add a structured mitigation to a threat"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    # Create new mitigation
    mitigation = StructuredMitigation(
        text=request.text,
        mitigation_type=request.mitigation_type,
        status=request.status,
        owner=request.owner,
        verification=request.verification
    )
    
    # Ensure structured_mitigations exists
    if "structured_mitigations" not in threat:
        threat["structured_mitigations"] = []
    
    threat["structured_mitigations"].append(mitigation.model_dump())
    
    # Also add to legacy mitigations for backward compat
    if "mitigations" not in threat:
        threat["mitigations"] = []
    threat["mitigations"].append(request.text)
    
    threat["updated_at"] = datetime.utcnow().isoformat()
    
    await threat_repo.save(threat_id, threat)
    
    audit_logger.log_data_access("api", "mitigation", threat_id, action="add")
    
    return {
        "id": threat_id,
        "mitigation": mitigation.model_dump(),
        "status": "added"
    }


@router.put("/{threat_id}/mitigations/{mitigation_id}")
async def update_structured_mitigation(
    threat_id: str,
    mitigation_id: str,
    request: StructuredMitigationRequest
):
    """Update a specific structured mitigation"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    structured = threat.get("structured_mitigations", [])
    
    # Find the mitigation
    found_idx = None
    for idx, m in enumerate(structured):
        if m.get("id") == mitigation_id:
            found_idx = idx
            break
    
    if found_idx is None:
        raise HTTPException(404, "Mitigation not found")
    
    # Update the mitigation
    old_text = structured[found_idx].get("text", "")
    structured[found_idx].update({
        "text": request.text,
        "mitigation_type": request.mitigation_type.value,
        "status": request.status.value,
        "owner": request.owner,
        "verification": request.verification,
        "updated_at": datetime.utcnow().isoformat()
    })
    
    threat["structured_mitigations"] = structured
    
    # Update legacy mitigations if text changed
    if old_text != request.text and "mitigations" in threat:
        threat["mitigations"] = [
            request.text if m == old_text else m
            for m in threat["mitigations"]
        ]
    
    threat["updated_at"] = datetime.utcnow().isoformat()
    
    await threat_repo.save(threat_id, threat)
    
    return {
        "id": threat_id,
        "mitigation_id": mitigation_id,
        "mitigation": structured[found_idx],
        "status": "updated"
    }


@router.delete("/{threat_id}/mitigations/{mitigation_id}")
async def delete_structured_mitigation(threat_id: str, mitigation_id: str):
    """Delete a specific structured mitigation"""
    threat = await threat_repo.load(threat_id)
    if not threat:
        raise HTTPException(404, "Threat not found")
    
    structured = threat.get("structured_mitigations", [])
    
    # Find and remove the mitigation
    removed_text = None
    new_structured = []
    for m in structured:
        if m.get("id") == mitigation_id:
            removed_text = m.get("text", "")
        else:
            new_structured.append(m)
    
    if removed_text is None:
        raise HTTPException(404, "Mitigation not found")
    
    threat["structured_mitigations"] = new_structured
    
    # Remove from legacy mitigations
    if "mitigations" in threat:
        threat["mitigations"] = [m for m in threat["mitigations"] if m != removed_text]
    
    threat["updated_at"] = datetime.utcnow().isoformat()
    
    await threat_repo.save(threat_id, threat)
    
    return {"id": threat_id, "mitigation_id": mitigation_id, "status": "deleted"}


# ===========================================
# Flow Map Endpoints
# ===========================================

@router.get("/{analysis_id}/flow-map")
async def get_flow_map(analysis_id: str):
    """Get flow map components and flows for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    flow_map = await get_flow_map_for_analysis(analysis_id)
    
    return {
        "analysis_id": analysis_id,
        "components": [c.model_dump() for c in flow_map.components],
        "flows": [f.model_dump(by_alias=True) for f in flow_map.flows],
        "trust_boundaries": flow_map.trust_boundaries
    }


@router.get("/{analysis_id}/flow-map/components")
async def get_flow_map_components(analysis_id: str):
    """Get just the components for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    flow_map = await get_flow_map_for_analysis(analysis_id)
    
    return {
        "analysis_id": analysis_id,
        "components": [c.model_dump() for c in flow_map.components],
        "count": len(flow_map.components)
    }


@router.get("/{analysis_id}/flow-map/flows")
async def get_flow_map_flows(analysis_id: str):
    """Get just the flows for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    flow_map = await get_flow_map_for_analysis(analysis_id)
    
    return {
        "analysis_id": analysis_id,
        "flows": [f.model_dump(by_alias=True) for f in flow_map.flows],
        "count": len(flow_map.flows)
    }


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
async def update_diagram(analysis_id: str, request: DiagramUpdateRequest):
    """Update diagram for an analysis"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    # Update diagram metadata
    diagram_metadata = {
        "zones": request.zones or [],
        "trust_boundaries": request.trust_boundaries or [],
        "components": request.components or [],
        "data_flows": request.data_flows or [],
        "updated_at": datetime.utcnow().isoformat()
    }
    
    await analysis_repo.update(
        analysis_id,
        dfd_mermaid=request.mermaid_code,
        metadata={**analysis.metadata, "diagram": diagram_metadata}
    )
    
    audit_logger.log_data_access("api", "diagram", analysis_id, action="update")
    
    return {
        "analysis_id": analysis_id,
        "status": "updated",
        "mermaid_code": request.mermaid_code
    }


# ===========================================
# Zones & Trust Boundaries
# ===========================================

@router.post("/{analysis_id}/zones")
async def add_zone(analysis_id: str, zone: ZoneCreateRequest):
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
    await analysis_repo.update(
        analysis_id,
        metadata={**analysis.metadata, "diagram": diagram_meta}
    )
    
    return {"zone": zone_data, "status": "saved"}


@router.post("/{analysis_id}/trust-boundaries")
async def add_trust_boundary(analysis_id: str, boundary: TrustBoundaryCreateRequest):
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
    await analysis_repo.update(
        analysis_id,
        metadata={**analysis.metadata, "diagram": diagram_meta}
    )
    
    return {"trust_boundary": boundary_data, "status": "saved"}


# ===========================================
# Export
# ===========================================

@router.get("/{analysis_id}/export")
async def export_threat_model(analysis_id: str, format: str = "json"):
    """Export complete threat model with enhanced data"""
    analysis = await analysis_repo.get(analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    project = await project_repo.get(analysis.project_id)
    
    # Enrich all threats
    enriched_threats = [enrich_threat_data(t) for t in analysis.threats]
    
    export_data = {
        "version": "2.0",  # Bumped for enhanced schema
        "schema_version": "enhanced_v1",
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
        "threats": enriched_threats,
        "compliance": analysis.compliance_summary,
        "summary": analysis.summary
    }
    
    return export_data


# ===========================================
# Risk Scoring Utilities
# ===========================================

@router.get("/utils/risk-breakdown")
async def get_risk_breakdown(
    damage: float = Query(5, ge=1, le=10),
    reproducibility: float = Query(5, ge=1, le=10),
    exploitability: float = Query(5, ge=1, le=10),
    affected_users: float = Query(5, ge=1, le=10),
    discoverability: float = Query(5, ge=1, le=10)
):
    """Calculate and explain DREAD risk score"""
    breakdown = dread_engine.get_risk_breakdown({
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affected_users": affected_users,
        "discoverability": discoverability
    })
    
    return breakdown


@router.post("/utils/infer-mitigation-type")
async def infer_mitigation_type_endpoint(text: str):
    """Infer mitigation type from text"""
    mit_type = infer_mitigation_type(text)
    return {
        "text": text,
        "inferred_type": mit_type.value,
        "type_description": {
            "prevent": "Controls that prevent the threat from being exploited",
            "detect": "Controls that detect when the threat is being exploited",
            "respond": "Controls that respond to and recover from exploitation"
        }[mit_type.value]
    }