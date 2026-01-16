"""
Mermaid.js Diagram Generator
Generates Data Flow Diagrams for threat modeling visualization
"""

from typing import Dict, Any, List, Optional
import structlog

logger = structlog.get_logger()


class MermaidGenerator:
    """
    Generates Mermaid.js diagrams for security visualization.
    
    Supports:
    - Flowcharts (DFDs)
    - Sequence diagrams
    - Class diagrams
    """
    
    # Default styling
    STYLES = {
        "default": {
            "external": "fill:#e1f5fe,stroke:#0277bd,stroke-width:2px",
            "process": "fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px",
            "datastore": "fill:#fff3e0,stroke:#ef6c00,stroke-width:2px",
            "threat": "fill:#ffebee,stroke:#c62828,stroke-width:3px",
            "trust_boundary": "fill:#f5f5f5,stroke:#9e9e9e,stroke-dasharray:5 5"
        },
        "dark": {
            "external": "fill:#1e3a5f,stroke:#64b5f6,stroke-width:2px,color:#fff",
            "process": "fill:#1b5e20,stroke:#81c784,stroke-width:2px,color:#fff",
            "datastore": "fill:#e65100,stroke:#ffb74d,stroke-width:2px,color:#fff",
            "threat": "fill:#b71c1c,stroke:#ef9a9a,stroke-width:3px,color:#fff",
            "trust_boundary": "fill:#212121,stroke:#757575,stroke-dasharray:5 5"
        },
        "colorful": {
            "external": "fill:#bbdefb,stroke:#1976d2,stroke-width:2px",
            "process": "fill:#c8e6c9,stroke:#388e3c,stroke-width:2px",
            "datastore": "fill:#ffe0b2,stroke:#f57c00,stroke-width:2px",
            "threat": "fill:#ffcdd2,stroke:#d32f2f,stroke-width:3px",
            "trust_boundary": "fill:#f3e5f5,stroke:#7b1fa2,stroke-dasharray:5 5"
        }
    }
    
    # Component icons
    ICONS = {
        "user": "👤",
        "admin": "👔",
        "external_api": "🌐",
        "web_app": "🖥️",
        "mobile_app": "📱",
        "api_gateway": "🚪",
        "auth_service": "🔐",
        "core_api": "⚙️",
        "database": "💾",
        "cache": "⚡",
        "file_storage": "📁",
        "message_queue": "📨",
        "load_balancer": "⚖️",
        "cdn": "🌍",
        "firewall": "🛡️"
    }
    
    def __init__(self):
        pass
    
    async def generate_dfd(
        self,
        project_data: Dict[str, Any],
        analysis_data: Optional[Dict[str, Any]] = None,
        diagram_type: str = "flowchart",
        include_trust_boundaries: bool = True,
        highlight_threats: bool = True,
        style: str = "default"
    ) -> Dict[str, Any]:
        """
        Generate a Data Flow Diagram.
        
        Args:
            project_data: Project metadata
            analysis_data: Optional analysis results
            diagram_type: Type of diagram
            include_trust_boundaries: Include trust boundary boxes
            highlight_threats: Highlight components with threats
            style: Visual style
        
        Returns:
            Mermaid code and metadata
        """
        # Extract components and flows
        components = await self.extract_components(project_data)
        flows = await self.extract_flows(project_data)
        
        # Get threat locations if available
        threat_locations = set()
        if analysis_data and highlight_threats:
            for threat in analysis_data.get("threats", []):
                component = threat.get("affected_component", "")
                threat_locations.add(component.lower())
        
        # Generate Mermaid code based on diagram type
        if diagram_type == "flowchart":
            mermaid_code = self._generate_flowchart(
                components,
                flows,
                threat_locations,
                include_trust_boundaries,
                style
            )
        elif diagram_type == "sequence":
            mermaid_code = self._generate_sequence_diagram(components, flows)
        else:
            mermaid_code = self._generate_flowchart(
                components,
                flows,
                threat_locations,
                include_trust_boundaries,
                style
            )
        
        return {
            "mermaid_code": mermaid_code,
            "components": components,
            "flows": flows,
            "metadata": {
                "diagram_type": diagram_type,
                "style": style,
                "has_trust_boundaries": include_trust_boundaries,
                "threat_locations": list(threat_locations)
            }
        }
    
    async def extract_components(
        self,
        project_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract system components from project data"""
        # Default component set for a typical web application
        components = [
            {
                "id": "user",
                "name": "User",
                "type": "external_entity",
                "trust_level": "untrusted",
                "icon": self.ICONS.get("user", "👤")
            },
            {
                "id": "admin",
                "name": "Admin",
                "type": "external_entity",
                "trust_level": "trusted",
                "icon": self.ICONS.get("admin", "👔")
            },
            {
                "id": "web_app",
                "name": "Web Application",
                "type": "process",
                "trust_level": "semi-trusted",
                "layer": "frontend",
                "icon": self.ICONS.get("web_app", "🖥️")
            },
            {
                "id": "api_gateway",
                "name": "API Gateway",
                "type": "process",
                "trust_level": "trusted",
                "layer": "backend",
                "icon": self.ICONS.get("api_gateway", "🚪")
            },
            {
                "id": "auth_service",
                "name": "Auth Service",
                "type": "process",
                "trust_level": "trusted",
                "layer": "backend",
                "icon": self.ICONS.get("auth_service", "🔐")
            },
            {
                "id": "core_api",
                "name": "Core API",
                "type": "process",
                "trust_level": "trusted",
                "layer": "backend",
                "icon": self.ICONS.get("core_api", "⚙️")
            },
            {
                "id": "database",
                "name": "Database",
                "type": "data_store",
                "trust_level": "trusted",
                "layer": "data",
                "icon": self.ICONS.get("database", "💾")
            },
            {
                "id": "cache",
                "name": "Cache",
                "type": "data_store",
                "trust_level": "trusted",
                "layer": "data",
                "icon": self.ICONS.get("cache", "⚡")
            },
            {
                "id": "external_api",
                "name": "External API",
                "type": "external_entity",
                "trust_level": "untrusted",
                "icon": self.ICONS.get("external_api", "🌐")
            }
        ]
        
        return components
    
    async def extract_flows(
        self,
        project_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract data flows from project data"""
        flows = [
            {
                "id": "f1",
                "source": "user",
                "target": "web_app",
                "label": "HTTPS",
                "data_type": "User Input",
                "protocol": "HTTPS",
                "encrypted": True
            },
            {
                "id": "f2",
                "source": "admin",
                "target": "web_app",
                "label": "HTTPS + MFA",
                "data_type": "Admin Commands",
                "protocol": "HTTPS",
                "encrypted": True
            },
            {
                "id": "f3",
                "source": "web_app",
                "target": "api_gateway",
                "label": "API Calls",
                "data_type": "JSON",
                "protocol": "REST",
                "encrypted": True
            },
            {
                "id": "f4",
                "source": "api_gateway",
                "target": "auth_service",
                "label": "Auth Check",
                "data_type": "JWT",
                "protocol": "gRPC",
                "encrypted": True
            },
            {
                "id": "f5",
                "source": "api_gateway",
                "target": "core_api",
                "label": "Business Logic",
                "data_type": "JSON",
                "protocol": "REST",
                "encrypted": True
            },
            {
                "id": "f6",
                "source": "auth_service",
                "target": "database",
                "label": "User Data",
                "data_type": "Credentials",
                "protocol": "SQL",
                "encrypted": True
            },
            {
                "id": "f7",
                "source": "core_api",
                "target": "database",
                "label": "CRUD",
                "data_type": "App Data",
                "protocol": "SQL",
                "encrypted": True
            },
            {
                "id": "f8",
                "source": "core_api",
                "target": "cache",
                "label": "Session",
                "data_type": "Session Data",
                "protocol": "Redis",
                "encrypted": False
            },
            {
                "id": "f9",
                "source": "core_api",
                "target": "external_api",
                "label": "External Call",
                "data_type": "API Data",
                "protocol": "HTTPS",
                "encrypted": True
            }
        ]
        
        return flows
    
    def _generate_flowchart(
        self,
        components: List[Dict[str, Any]],
        flows: List[Dict[str, Any]],
        threat_locations: set,
        include_trust_boundaries: bool,
        style: str
    ) -> str:
        """Generate Mermaid flowchart"""
        lines = ["flowchart TB"]
        styles = self.STYLES.get(style, self.STYLES["default"])
        
        # Add styling definitions
        lines.append("")
        lines.append("    %% Styling")
        lines.append(f"    classDef external {styles['external']}")
        lines.append(f"    classDef process {styles['process']}")
        lines.append(f"    classDef datastore {styles['datastore']}")
        lines.append(f"    classDef threat {styles['threat']}")
        lines.append("")
        
        if include_trust_boundaries:
            # Group components by layer
            external_components = [c for c in components if c["type"] == "external_entity"]
            frontend_components = [c for c in components if c.get("layer") == "frontend"]
            backend_components = [c for c in components if c.get("layer") == "backend"]
            data_components = [c for c in components if c.get("layer") == "data"]
            
            # External entities
            lines.append("    subgraph External[\"External Entities\"]")
            for comp in external_components:
                shape = self._get_shape(comp["type"], comp)
                lines.append(f"        {comp['id']}{shape}")
            lines.append("    end")
            lines.append("")
            
            # Trust boundary
            lines.append("    subgraph TrustBoundary[\"Trust Boundary\"]")
            
            # Frontend layer
            if frontend_components:
                lines.append("        subgraph Frontend[\"Frontend Layer\"]")
                for comp in frontend_components:
                    shape = self._get_shape(comp["type"], comp)
                    lines.append(f"            {comp['id']}{shape}")
                lines.append("        end")
                lines.append("")
            
            # Backend layer
            if backend_components:
                lines.append("        subgraph Backend[\"Backend Layer\"]")
                for comp in backend_components:
                    shape = self._get_shape(comp["type"], comp)
                    lines.append(f"            {comp['id']}{shape}")
                lines.append("        end")
                lines.append("")
            
            # Data layer
            if data_components:
                lines.append("        subgraph Data[\"Data Layer\"]")
                for comp in data_components:
                    shape = self._get_shape(comp["type"], comp)
                    lines.append(f"            {comp['id']}{shape}")
                lines.append("        end")
            
            lines.append("    end")
            lines.append("")
        else:
            # Flat structure without trust boundaries
            for comp in components:
                shape = self._get_shape(comp["type"], comp)
                lines.append(f"    {comp['id']}{shape}")
            lines.append("")
        
        # Add flows
        lines.append("    %% Data Flows")
        for flow in flows:
            encrypted_icon = "🔒" if flow.get("encrypted") else "⚠️"
            lines.append(f"    {flow['source']} -->|\"{encrypted_icon} {flow['label']}\"| {flow['target']}")
        lines.append("")
        
        # Apply styles
        lines.append("    %% Apply Styles")
        
        external_ids = [c["id"] for c in components if c["type"] == "external_entity"]
        process_ids = [c["id"] for c in components if c["type"] == "process"]
        datastore_ids = [c["id"] for c in components if c["type"] == "data_store"]
        
        # Mark threat locations
        threat_ids = []
        for comp in components:
            comp_name = comp["name"].lower()
            if any(loc in comp_name or comp_name in loc for loc in threat_locations):
                threat_ids.append(comp["id"])
        
        if external_ids:
            lines.append(f"    class {','.join(external_ids)} external")
        if process_ids:
            non_threat_process = [p for p in process_ids if p not in threat_ids]
            if non_threat_process:
                lines.append(f"    class {','.join(non_threat_process)} process")
        if datastore_ids:
            non_threat_data = [d for d in datastore_ids if d not in threat_ids]
            if non_threat_data:
                lines.append(f"    class {','.join(non_threat_data)} datastore")
        if threat_ids:
            lines.append(f"    class {','.join(threat_ids)} threat")
        
        return "\n".join(lines)
    
    def _generate_sequence_diagram(
        self,
        components: List[Dict[str, Any]],
        flows: List[Dict[str, Any]]
    ) -> str:
        """Generate Mermaid sequence diagram"""
        lines = ["sequenceDiagram"]
        lines.append("    autonumber")
        lines.append("")
        
        # Add participants
        for comp in components:
            alias = comp["name"].replace(" ", "_")
            lines.append(f"    participant {comp['id']} as {comp['icon']} {comp['name']}")
        lines.append("")
        
        # Add flows as interactions
        for flow in flows:
            encrypted = "🔒" if flow.get("encrypted") else "⚠️"
            lines.append(f"    {flow['source']}->>+{flow['target']}: {encrypted} {flow['label']}")
        
        return "\n".join(lines)
    
    def _get_shape(
        self,
        component_type: str,
        component: Dict[str, Any]
    ) -> str:
        """Get Mermaid shape for component type"""
        icon = component.get("icon", "")
        name = component.get("name", "Unknown")
        
        if component_type == "external_entity":
            return f"[(\"{icon} {name}\")]"
        elif component_type == "process":
            return f"[\"{icon} {name}\"]"
        elif component_type == "data_store":
            return f"[(\"{icon} {name}\")]"
        else:
            return f"[\"{icon} {name}\"]"
    
    def generate_attack_tree(
        self,
        root_goal: str,
        attack_paths: List[Dict[str, Any]]
    ) -> str:
        """Generate attack tree diagram"""
        lines = ["flowchart TD"]
        lines.append(f"    root[\"🎯 {root_goal}\"]")
        lines.append("")
        
        for idx, path in enumerate(attack_paths):
            path_id = f"path{idx}"
            lines.append(f"    {path_id}[\"⚔️ {path.get('name', 'Attack Path')}\"]")
            lines.append(f"    root --> {path_id}")
            
            # Add steps
            for step_idx, step in enumerate(path.get("steps", [])):
                step_id = f"{path_id}_step{step_idx}"
                lines.append(f"    {step_id}[\"• {step}\"]")
                if step_idx == 0:
                    lines.append(f"    {path_id} --> {step_id}")
                else:
                    prev_step_id = f"{path_id}_step{step_idx - 1}"
                    lines.append(f"    {prev_step_id} --> {step_id}")
        
        return "\n".join(lines)


