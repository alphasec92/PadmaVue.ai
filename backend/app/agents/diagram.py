"""
Diagram Agent
Generates Mermaid.js Data Flow Diagrams
"""

from typing import Dict, Any, List, Optional
import json

import structlog

from app.services.llm_provider import LLMProvider
from app.generators.mermaid import MermaidGenerator

logger = structlog.get_logger()


class DiagramAgent:
    """
    Diagram Agent for generating Data Flow Diagrams.
    
    Capabilities:
    - Generate Mermaid.js flowcharts
    - Mark trust boundaries
    - Highlight threat locations
    - Show data flows
    """
    
    SYSTEM_PROMPT = """You are a Security Diagram Agent specialized in creating 
Data Flow Diagrams (DFDs) for threat modeling.

Your diagrams should:
1. Show all system components clearly
2. Mark trust boundaries
3. Indicate data flows with labels
4. Highlight sensitive data paths
5. Use appropriate Mermaid.js syntax

Component types to identify:
- External Entities (users, external systems)
- Processes (services, APIs, applications)
- Data Stores (databases, caches, file systems)
- Trust Boundaries (network zones, security domains)

Use clear, consistent styling for security visualization."""
    
    def __init__(self, llm: LLMProvider):
        self.llm = llm
        self.mermaid_generator = MermaidGenerator()
    
    async def run(
        self,
        project_data: Dict[str, Any],
        threat_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate DFD diagram for the project.
        
        Args:
            project_data: Project metadata
            threat_results: Threat analysis results
        
        Returns:
            Diagram results with Mermaid code
        """
        logger.info("Generating DFD diagram")
        
        # Extract components and flows
        components = await self._extract_components(project_data, threat_results)
        flows = await self._extract_flows(components)
        
        # Generate Mermaid diagram
        mermaid_code = self._generate_mermaid(components, flows, threat_results)
        
        logger.info("DFD diagram generated",
                   components=len(components),
                   flows=len(flows))
        
        return {
            "mermaid_code": mermaid_code,
            "components": components,
            "flows": flows,
            "metadata": {
                "diagram_type": "flowchart",
                "has_trust_boundaries": True,
                "threat_annotations": True
            }
        }
    
    async def _extract_components(
        self,
        project_data: Dict[str, Any],
        threat_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract system components"""
        # Get affected components from threats
        threat_components = set()
        for threat in threat_results.get("threats", []):
            component = threat.get("affected_component", "")
            if component:
                threat_components.add(component)
        
        # Build component list
        components = [
            {
                "id": "user",
                "name": "User",
                "type": "external_entity",
                "trust_level": "untrusted",
                "has_threats": "User" in threat_components or "External" in str(threat_components)
            },
            {
                "id": "admin",
                "name": "Admin",
                "type": "external_entity",
                "trust_level": "trusted",
                "has_threats": "Admin" in threat_components
            },
            {
                "id": "web_app",
                "name": "Web Application",
                "type": "process",
                "trust_level": "semi-trusted",
                "has_threats": any(c for c in threat_components if "web" in c.lower() or "frontend" in c.lower())
            },
            {
                "id": "api_gateway",
                "name": "API Gateway",
                "type": "process",
                "trust_level": "trusted",
                "has_threats": any(c for c in threat_components if "api" in c.lower() or "gateway" in c.lower())
            },
            {
                "id": "auth_service",
                "name": "Auth Service",
                "type": "process",
                "trust_level": "trusted",
                "has_threats": any(c for c in threat_components if "auth" in c.lower())
            },
            {
                "id": "core_api",
                "name": "Core API",
                "type": "process",
                "trust_level": "trusted",
                "has_threats": any(c for c in threat_components if "core" in c.lower() or "service" in c.lower())
            },
            {
                "id": "database",
                "name": "Database",
                "type": "data_store",
                "trust_level": "trusted",
                "has_threats": any(c for c in threat_components if "database" in c.lower() or "db" in c.lower())
            },
            {
                "id": "cache",
                "name": "Cache",
                "type": "data_store",
                "trust_level": "trusted",
                "has_threats": any(c for c in threat_components if "cache" in c.lower())
            },
            {
                "id": "external_api",
                "name": "External API",
                "type": "external_entity",
                "trust_level": "untrusted",
                "has_threats": any(c for c in threat_components if "external" in c.lower())
            }
        ]
        
        return components
    
    async def _extract_flows(
        self,
        components: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract data flows between components"""
        flows = [
            {
                "id": "f1",
                "source": "user",
                "target": "web_app",
                "label": "HTTPS",
                "data_type": "User Input",
                "encrypted": True
            },
            {
                "id": "f2",
                "source": "admin",
                "target": "web_app",
                "label": "HTTPS + MFA",
                "data_type": "Admin Commands",
                "encrypted": True
            },
            {
                "id": "f3",
                "source": "web_app",
                "target": "api_gateway",
                "label": "API Calls",
                "data_type": "JSON",
                "encrypted": True
            },
            {
                "id": "f4",
                "source": "api_gateway",
                "target": "auth_service",
                "label": "Auth Check",
                "data_type": "JWT",
                "encrypted": True
            },
            {
                "id": "f5",
                "source": "api_gateway",
                "target": "core_api",
                "label": "Business Logic",
                "data_type": "JSON",
                "encrypted": True
            },
            {
                "id": "f6",
                "source": "auth_service",
                "target": "database",
                "label": "User Data",
                "data_type": "Credentials",
                "encrypted": True
            },
            {
                "id": "f7",
                "source": "core_api",
                "target": "database",
                "label": "CRUD",
                "data_type": "App Data",
                "encrypted": True
            },
            {
                "id": "f8",
                "source": "core_api",
                "target": "cache",
                "label": "Session",
                "data_type": "Session Data",
                "encrypted": False
            },
            {
                "id": "f9",
                "source": "core_api",
                "target": "external_api",
                "label": "External Call",
                "data_type": "API Data",
                "encrypted": True
            }
        ]
        
        return flows
    
    def _generate_mermaid(
        self,
        components: List[Dict[str, Any]],
        flows: List[Dict[str, Any]],
        threat_results: Dict[str, Any]
    ) -> str:
        """Generate Mermaid.js diagram code"""
        lines = ["flowchart TB"]
        
        # Add styling
        lines.append("")
        lines.append("    %% Styling")
        lines.append("    classDef external fill:#e1f5fe,stroke:#0277bd,stroke-width:2px")
        lines.append("    classDef process fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px")
        lines.append("    classDef datastore fill:#fff3e0,stroke:#ef6c00,stroke-width:2px")
        lines.append("    classDef threat fill:#ffebee,stroke:#c62828,stroke-width:3px")
        lines.append("")
        
        # External entities subgraph
        lines.append("    subgraph External[\"External Entities\"]")
        for comp in components:
            if comp["type"] == "external_entity":
                icon = "👤" if "user" in comp["id"].lower() else "👔" if "admin" in comp["id"].lower() else "🌐"
                lines.append(f"        {comp['id']}[(\"{icon} {comp['name']}\")]")
        lines.append("    end")
        lines.append("")
        
        # Trust boundary
        lines.append("    subgraph TrustBoundary[\"Trust Boundary\"]")
        
        # Frontend layer
        lines.append("        subgraph Frontend[\"Frontend Layer\"]")
        for comp in components:
            if comp["type"] == "process" and "web" in comp["id"].lower():
                lines.append(f"            {comp['id']}[\"🖥️ {comp['name']}\"]")
        lines.append("        end")
        lines.append("")
        
        # Backend layer
        lines.append("        subgraph Backend[\"Backend Layer\"]")
        for comp in components:
            if comp["type"] == "process" and "web" not in comp["id"].lower():
                icon = "🚪" if "gateway" in comp["id"] else "🔐" if "auth" in comp["id"] else "⚙️"
                lines.append(f"            {comp['id']}[\"{icon} {comp['name']}\"]")
        lines.append("        end")
        lines.append("")
        
        # Data layer
        lines.append("        subgraph Data[\"Data Layer\"]")
        for comp in components:
            if comp["type"] == "data_store":
                icon = "💾" if "database" in comp["id"] else "⚡"
                lines.append(f"            {comp['id']}[(\"{icon} {comp['name']}\")]")
        lines.append("        end")
        lines.append("    end")
        lines.append("")
        
        # Add flows
        lines.append("    %% Data Flows")
        for flow in flows:
            encrypted = "🔒" if flow.get("encrypted") else "⚠️"
            lines.append(f"    {flow['source']} -->|\"{encrypted} {flow['label']}\"| {flow['target']}")
        lines.append("")
        
        # Apply styles
        lines.append("    %% Apply Styles")
        external_ids = [c["id"] for c in components if c["type"] == "external_entity"]
        process_ids = [c["id"] for c in components if c["type"] == "process"]
        datastore_ids = [c["id"] for c in components if c["type"] == "data_store"]
        threat_ids = [c["id"] for c in components if c.get("has_threats")]
        
        if external_ids:
            lines.append(f"    class {','.join(external_ids)} external")
        if process_ids:
            lines.append(f"    class {','.join(process_ids)} process")
        if datastore_ids:
            lines.append(f"    class {','.join(datastore_ids)} datastore")
        if threat_ids:
            lines.append(f"    class {','.join(threat_ids)} threat")
        
        return "\n".join(lines)
    
    async def generate_sequence_diagram(
        self,
        flow_name: str,
        components: List[str]
    ) -> str:
        """Generate a sequence diagram for a specific flow"""
        lines = ["sequenceDiagram"]
        lines.append("    autonumber")
        lines.append("")
        
        # Add participants
        for comp in components:
            lines.append(f"    participant {comp}")
        lines.append("")
        
        # Add sample interactions
        if len(components) >= 2:
            lines.append(f"    {components[0]}->>+{components[1]}: Request")
            if len(components) >= 3:
                lines.append(f"    {components[1]}->>+{components[2]}: Process")
                lines.append(f"    {components[2]}-->>-{components[1]}: Response")
            lines.append(f"    {components[1]}-->>-{components[0]}: Result")
        
        return "\n".join(lines)


