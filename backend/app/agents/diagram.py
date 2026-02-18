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
        """Extract system components from threats and project data"""
        # Get affected components from threats
        threat_components = {}  # component_name -> threat_count
        zones = {}  # component_name -> zone
        
        for threat in threat_results.get("threats", []):
            component = threat.get("affected_component", "")
            if component:
                threat_components[component] = threat_components.get(component, 0) + 1
                # Try to get zone info
                if "zone" in threat:
                    zones[component] = threat["zone"]
        
        # Build component list from actual threats
        components = []
        component_id_map = {}
        
        # Process each unique component found in threats
        for component_name in threat_components.keys():
            component_id = component_name.lower().replace(" ", "_").replace("-", "_")
            # Avoid duplicate IDs
            if component_id in component_id_map:
                component_id = f"{component_id}_{len(component_id_map)}"
            component_id_map[component_id] = component_name
            
            # Infer component type and trust level from name
            comp_lower = component_name.lower()
            
            if any(k in comp_lower for k in ["user", "client", "browser", "external", "third-party", "3rd party"]):
                comp_type = "external_entity"
                trust_level = "untrusted"
            elif any(k in comp_lower for k in ["database", "db", "storage", "cache", "redis", "postgres", "mysql", "mongodb"]):
                comp_type = "data_store"
                trust_level = "trusted"
            else:
                comp_type = "process"
                # Check if it's auth/admin related (higher trust)
                if any(k in comp_lower for k in ["auth", "admin", "security"]):
                    trust_level = "trusted"
                elif any(k in comp_lower for k in ["frontend", "web", "ui", "client"]):
                    trust_level = "semi-trusted"
                else:
                    trust_level = "trusted"
            
            components.append({
                "id": component_id,
                "name": component_name,
                "type": comp_type,
                "trust_level": trust_level,
                "has_threats": True,
                "threat_count": threat_components[component_name],
                "zone": zones.get(component_name)
            })
        
        # If no components found (shouldn't happen), use fallback minimal set
        if not components:
            logger.warning("No components extracted from threats, using minimal fallback")
            components = [
                {
                    "id": "user",
                    "name": "User",
                    "type": "external_entity",
                    "trust_level": "untrusted",
                    "has_threats": False
                },
                {
                    "id": "application",
                    "name": "Application",
                    "type": "process",
                    "trust_level": "semi-trusted",
                    "has_threats": False
                },
                {
                    "id": "database",
                    "name": "Database",
                    "type": "data_store",
                    "trust_level": "trusted",
                    "has_threats": False
                }
            ]
        
        logger.info("Extracted components from threats", count=len(components), components=[c["name"] for c in components])
        return components
    
    async def _extract_flows(
        self,
        components: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Infer data flows between components based on typical architecture patterns"""
        flows = []
        flow_id = 1
        
        # Create a mapping for quick lookup
        comp_map = {c["id"]: c for c in components}
        
        # Get component IDs by type
        external_entities = [c["id"] for c in components if c["type"] == "external_entity"]
        processes = [c["id"] for c in components if c["type"] == "process"]
        data_stores = [c["id"] for c in components if c["type"] == "data_store"]
        
        # Pattern 1: External entities -> Processes (frontend/gateway)
        for ext in external_entities:
            # Find frontend/web processes
            frontends = [p for p in processes if any(k in comp_map[p]["name"].lower() for k in ["web", "frontend", "ui", "app", "client"])]
            if frontends:
                for frontend in frontends[:1]:  # Connect to first frontend
                    flows.append({
                        "id": f"f{flow_id}",
                        "source": ext,
                        "target": frontend,
                        "label": "HTTPS",
                        "data_type": "User Input",
                        "encrypted": True
                    })
                    flow_id += 1
            else:
                # If no frontend, connect to first process (e.g., API)
                if processes:
                    flows.append({
                        "id": f"f{flow_id}",
                        "source": ext,
                        "target": processes[0],
                        "label": "HTTPS",
                        "data_type": "User Input",
                        "encrypted": True
                    })
                    flow_id += 1
        
        # Pattern 2: Frontend/Web -> Backend/API processes
        frontends = [p for p in processes if any(k in comp_map[p]["name"].lower() for k in ["web", "frontend", "ui", "client"])]
        backends = [p for p in processes if p not in frontends]
        
        for frontend in frontends:
            # Connect to API/Gateway/Backend
            apis = [b for b in backends if any(k in comp_map[b]["name"].lower() for k in ["api", "gateway", "backend", "service"])]
            if apis:
                flows.append({
                    "id": f"f{flow_id}",
                    "source": frontend,
                    "target": apis[0],
                    "label": "API Calls",
                    "data_type": "JSON",
                    "encrypted": True
                })
                flow_id += 1
        
        # Pattern 3: Processes -> Data Stores
        for process in processes:
            process_name = comp_map[process]["name"].lower()
            
            # Auth service -> Database
            if "auth" in process_name and data_stores:
                dbs = [d for d in data_stores if "database" in comp_map[d]["name"].lower() or "db" in comp_map[d]["name"].lower()]
                if dbs:
                    flows.append({
                        "id": f"f{flow_id}",
                        "source": process,
                        "target": dbs[0],
                        "label": "User Data",
                        "data_type": "Credentials",
                        "encrypted": True
                    })
                    flow_id += 1
            
            # API/Service -> Database
            elif any(k in process_name for k in ["api", "service", "core", "backend"]) and data_stores:
                dbs = [d for d in data_stores if "database" in comp_map[d]["name"].lower() or "db" in comp_map[d]["name"].lower()]
                if dbs:
                    flows.append({
                        "id": f"f{flow_id}",
                        "source": process,
                        "target": dbs[0],
                        "label": "CRUD",
                        "data_type": "Application Data",
                        "encrypted": True
                    })
                    flow_id += 1
                
                # Also connect to cache if available
                caches = [d for d in data_stores if any(k in comp_map[d]["name"].lower() for k in ["cache", "redis", "memcache"])]
                if caches:
                    flows.append({
                        "id": f"f{flow_id}",
                        "source": process,
                        "target": caches[0],
                        "label": "Session/Cache",
                        "data_type": "Session Data",
                        "encrypted": False
                    })
                    flow_id += 1
        
        # Pattern 4: Process -> External entities (for external APIs, third-party services)
        external_services = [e for e in external_entities if any(k in comp_map[e]["name"].lower() for k in ["api", "service", "third", "external"])]
        for ext_svc in external_services:
            # Connect from backend processes
            backends = [p for p in processes if any(k in comp_map[p]["name"].lower() for k in ["api", "service", "backend", "core"])]
            if backends:
                flows.append({
                    "id": f"f{flow_id}",
                    "source": backends[0],
                    "target": ext_svc,
                    "label": "External API",
                    "data_type": "API Data",
                    "encrypted": True
                })
                flow_id += 1
        
        # Fallback: If no flows were created, create basic flow chain
        if not flows and len(components) >= 2:
            flows.append({
                "id": "f1",
                "source": components[0]["id"],
                "target": components[1]["id"],
                "label": "Data Flow",
                "data_type": "Data",
                "encrypted": True
            })
        
        logger.info("Inferred data flows", count=len(flows))
        return flows
    
    def _generate_mermaid(
        self,
        components: List[Dict[str, Any]],
        flows: List[Dict[str, Any]],
        threat_results: Dict[str, Any]
    ) -> str:
        """Generate Mermaid.js diagram code"""
        lines = ["flowchart TB"]
        
        # Add styling with better contrast for both light and dark modes
        lines.append("")
        lines.append("    %% Styling")
        lines.append("    classDef external fill:#dbeafe,stroke:#1e40af,stroke-width:2px,color:#1e3a8a")
        lines.append("    classDef process fill:#dcfce7,stroke:#15803d,stroke-width:2px,color:#14532d")
        lines.append("    classDef datastore fill:#fef3c7,stroke:#b45309,stroke-width:2px,color:#78350f")
        lines.append("    classDef threat fill:#fee2e2,stroke:#991b1b,stroke-width:3px,color:#7f1d1d")
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


