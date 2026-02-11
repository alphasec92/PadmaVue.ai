"""
Neo4j Client for GraphRAG
Manages graph database connections and operations for attack path analysis
"""

from typing import List, Dict, Any, Optional
import asyncio
from contextlib import asynccontextmanager

from neo4j import AsyncGraphDatabase, AsyncDriver
import structlog

from app.config import settings

logger = structlog.get_logger()


class Neo4jClient:
    """
    Neo4j client for GraphRAG operations.
    
    Manages:
    - Component relationships
    - Attack paths
    - Trust boundaries
    - Data flow graphs
    """
    
    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = settings.NEO4J_PASSWORD
        self.driver: Optional[AsyncDriver] = None
    
    async def connect(self):
        """Establish connection to Neo4j"""
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password)
            )
            # Verify connection
            async with self.driver.session() as session:
                await session.run("RETURN 1")
            logger.info("Neo4j connection established", uri=self.uri)
            
            # Initialize schema
            await self._initialize_schema()
            
        except Exception as e:
            logger.error("Failed to connect to Neo4j", error=str(e))
            raise
    
    async def close(self):
        """Close Neo4j connection"""
        if self.driver:
            await self.driver.close()
            logger.info("Neo4j connection closed")
    
    async def _initialize_schema(self):
        """Initialize graph schema with constraints and indexes"""
        constraints = [
            "CREATE CONSTRAINT component_id IF NOT EXISTS FOR (c:Component) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT threat_id IF NOT EXISTS FOR (t:Threat) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT project_id IF NOT EXISTS FOR (p:Project) REQUIRE p.id IS UNIQUE",
            "CREATE INDEX component_type IF NOT EXISTS FOR (c:Component) ON (c.type)",
            "CREATE INDEX threat_category IF NOT EXISTS FOR (t:Threat) ON (t.category)",
        ]
        
        async with self.driver.session() as session:
            for constraint in constraints:
                try:
                    await session.run(constraint)
                except Exception as e:
                    # Ignore if constraint already exists
                    pass
        
        logger.info("Neo4j schema initialized")
    
    async def create_project(self, project_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create a project node"""
        query = """
        MERGE (p:Project {id: $project_id})
        SET p.name = $name,
            p.description = $description,
            p.created_at = datetime(),
            p.metadata = $metadata
        RETURN p
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                project_id=project_id,
                name=metadata.get("project_name", ""),
                description=metadata.get("description", ""),
                metadata=str(metadata)
            )
            record = await result.single()
            return dict(record["p"]) if record else {}
    
    async def create_component(
        self,
        project_id: str,
        component_id: str,
        name: str,
        component_type: str,
        properties: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create a component node linked to a project"""
        query = """
        MATCH (p:Project {id: $project_id})
        MERGE (c:Component {id: $component_id})
        SET c.name = $name,
            c.type = $component_type,
            c.properties = $properties,
            c.created_at = datetime()
        MERGE (p)-[:HAS_COMPONENT]->(c)
        RETURN c
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                project_id=project_id,
                component_id=component_id,
                name=name,
                component_type=component_type,
                properties=str(properties or {})
            )
            record = await result.single()
            return dict(record["c"]) if record else {}
    
    async def create_data_flow(
        self,
        source_id: str,
        target_id: str,
        label: str,
        properties: Dict[str, Any] = None
    ) -> bool:
        """Create a data flow relationship between components"""
        query = """
        MATCH (s:Component {id: $source_id})
        MATCH (t:Component {id: $target_id})
        MERGE (s)-[r:DATA_FLOW {label: $label}]->(t)
        SET r.properties = $properties,
            r.created_at = datetime()
        RETURN r
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                source_id=source_id,
                target_id=target_id,
                label=label,
                properties=str(properties or {})
            )
            return await result.single() is not None
    
    async def create_threat(
        self,
        threat_id: str,
        category: str,
        title: str,
        properties: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a threat node"""
        query = """
        MERGE (t:Threat {id: $threat_id})
        SET t.category = $category,
            t.title = $title,
            t.severity = $severity,
            t.dread_score = $dread_score,
            t.properties = $properties,
            t.created_at = datetime()
        RETURN t
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                threat_id=threat_id,
                category=category,
                title=title,
                severity=properties.get("severity", "medium"),
                dread_score=properties.get("overall_risk", 5.0),
                properties=str(properties)
            )
            record = await result.single()
            return dict(record["t"]) if record else {}
    
    async def link_threat_to_component(
        self,
        threat_id: str,
        component_id: str
    ) -> bool:
        """Link a threat to an affected component"""
        query = """
        MATCH (t:Threat {id: $threat_id})
        MATCH (c:Component {id: $component_id})
        MERGE (t)-[:AFFECTS]->(c)
        RETURN t, c
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                threat_id=threat_id,
                component_id=component_id
            )
            return await result.single() is not None
    
    async def find_attack_paths(
        self,
        project_id: str,
        max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find potential attack paths in the graph.
        Uses graph traversal to identify chains of vulnerabilities.
        """
        query = """
        MATCH (p:Project {id: $project_id})-[:HAS_COMPONENT]->(entry:Component)
        WHERE entry.type IN ['external_entity', 'api_endpoint', 'user_interface']
        MATCH path = (entry)-[:DATA_FLOW*1..$max_depth]->(target:Component)
        WHERE target.type IN ['data_store', 'database', 'sensitive_data']
        WITH path, 
             [node in nodes(path) | node.name] as node_names,
             length(path) as path_length
        RETURN node_names, path_length
        ORDER BY path_length
        LIMIT 20
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                project_id=project_id,
                max_depth=max_depth
            )
            paths = []
            async for record in result:
                paths.append({
                    "nodes": record["node_names"],
                    "length": record["path_length"]
                })
            return paths
    
    async def get_component_threats(
        self,
        component_id: str
    ) -> List[Dict[str, Any]]:
        """Get all threats affecting a component"""
        query = """
        MATCH (t:Threat)-[:AFFECTS]->(c:Component {id: $component_id})
        RETURN t
        ORDER BY t.dread_score DESC
        """
        
        async with self.driver.session() as session:
            result = await session.run(query, component_id=component_id)
            threats = []
            async for record in result:
                threats.append(dict(record["t"]))
            return threats
    
    async def get_project_graph(
        self,
        project_id: str
    ) -> Dict[str, Any]:
        """Get the complete graph for a project"""
        # Get components
        components_query = """
        MATCH (p:Project {id: $project_id})-[:HAS_COMPONENT]->(c:Component)
        RETURN c
        """
        
        # Get relationships
        relationships_query = """
        MATCH (p:Project {id: $project_id})-[:HAS_COMPONENT]->(c1:Component)
        MATCH (c1)-[r:DATA_FLOW]->(c2:Component)
        RETURN c1.id as source, c2.id as target, r.label as label
        """
        
        # Get threats
        threats_query = """
        MATCH (p:Project {id: $project_id})-[:HAS_COMPONENT]->(c:Component)
        MATCH (t:Threat)-[:AFFECTS]->(c)
        RETURN t, c.id as component_id
        """
        
        async with self.driver.session() as session:
            # Execute all queries
            components_result = await session.run(components_query, project_id=project_id)
            relationships_result = await session.run(relationships_query, project_id=project_id)
            threats_result = await session.run(threats_query, project_id=project_id)
            
            components = []
            async for record in components_result:
                components.append(dict(record["c"]))
            
            relationships = []
            async for record in relationships_result:
                relationships.append({
                    "source": record["source"],
                    "target": record["target"],
                    "label": record["label"]
                })
            
            threats = []
            async for record in threats_result:
                threat_data = dict(record["t"])
                threat_data["component_id"] = record["component_id"]
                threats.append(threat_data)
            
            return {
                "project_id": project_id,
                "components": components,
                "relationships": relationships,
                "threats": threats
            }
    
    async def clear_project(self, project_id: str) -> bool:
        """Clear all data for a project"""
        query = """
        MATCH (p:Project {id: $project_id})
        OPTIONAL MATCH (p)-[:HAS_COMPONENT]->(c:Component)
        OPTIONAL MATCH (t:Threat)-[:AFFECTS]->(c)
        DETACH DELETE p, c, t
        """
        
        async with self.driver.session() as session:
            await session.run(query, project_id=project_id)
            return True
    
    async def run_query(self, query: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Run a custom Cypher query"""
        async with self.driver.session() as session:
            result = await session.run(query, params or {})
            records = []
            async for record in result:
                records.append(dict(record))
            return records
    
    # ===========================================
    # Enhanced Threat Operations (v2.0)
    # ===========================================
    
    async def create_threat_enhanced(
        self,
        threat_id: str,
        properties: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create an enhanced threat node with all v2.0 fields.
        Includes attack scenario, confidence, and scoring explanation.
        """
        query = """
        MERGE (t:Threat {id: $threat_id})
        SET t.title = $title,
            t.description = $description,
            t.category = $category,
            t.severity = $severity,
            t.overall_risk = $overall_risk,
            t.scoring_model = $scoring_model,
            t.scoring_explanation = $scoring_explanation,
            t.confidence = $confidence,
            t.attack_vector = $attack_vector,
            t.impact_narrative = $impact_narrative,
            t.stride_category = $stride_category,
            t.status = $status,
            t.created_at = datetime(),
            t.updated_at = datetime()
        RETURN t
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                threat_id=threat_id,
                title=properties.get("title", ""),
                description=properties.get("description", ""),
                category=properties.get("category", ""),
                severity=properties.get("severity", "medium"),
                overall_risk=properties.get("overall_risk", 5.0),
                scoring_model=properties.get("scoring_model", "DREAD_AVG_V1"),
                scoring_explanation=properties.get("scoring_explanation", ""),
                confidence=properties.get("confidence", "medium"),
                attack_vector=properties.get("attack_vector", ""),
                impact_narrative=properties.get("impact_narrative", ""),
                stride_category=properties.get("stride_category", ""),
                status=properties.get("status", "identified")
            )
            record = await result.single()
            return dict(record["t"]) if record else {}
    
    async def create_mitigation(
        self,
        mitigation_id: str,
        threat_id: str,
        properties: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a mitigation node linked to a threat.
        Supports structured mitigations with type, status, owner.
        """
        query = """
        MATCH (t:Threat {id: $threat_id})
        MERGE (m:Mitigation {id: $mitigation_id})
        SET m.text = $text,
            m.mitigation_type = $mitigation_type,
            m.status = $status,
            m.owner = $owner,
            m.verification = $verification,
            m.created_at = datetime(),
            m.updated_at = datetime()
        MERGE (t)-[:HAS_MITIGATION]->(m)
        RETURN m
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                mitigation_id=mitigation_id,
                threat_id=threat_id,
                text=properties.get("text", ""),
                mitigation_type=properties.get("mitigation_type", "prevent"),
                status=properties.get("status", "planned"),
                owner=properties.get("owner", ""),
                verification=str(properties.get("verification", []))
            )
            record = await result.single()
            return dict(record["m"]) if record else {}
    
    async def update_mitigation(
        self,
        mitigation_id: str,
        properties: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update a mitigation node"""
        query = """
        MATCH (m:Mitigation {id: $mitigation_id})
        SET m.text = COALESCE($text, m.text),
            m.mitigation_type = COALESCE($mitigation_type, m.mitigation_type),
            m.status = COALESCE($status, m.status),
            m.owner = COALESCE($owner, m.owner),
            m.verification = COALESCE($verification, m.verification),
            m.updated_at = datetime()
        RETURN m
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                mitigation_id=mitigation_id,
                text=properties.get("text"),
                mitigation_type=properties.get("mitigation_type"),
                status=properties.get("status"),
                owner=properties.get("owner"),
                verification=str(properties.get("verification")) if properties.get("verification") else None
            )
            record = await result.single()
            return dict(record["m"]) if record else {}
    
    async def link_threat_to_flow(
        self,
        threat_id: str,
        flow_id: str
    ) -> bool:
        """Link a threat to an impacted data flow"""
        query = """
        MATCH (t:Threat {id: $threat_id})
        MATCH (s:Component)-[f:DATA_FLOW]->(e:Component)
        WHERE f.id = $flow_id
        MERGE (t)-[:IMPACTS_FLOW]->(f)
        RETURN t, f
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                threat_id=threat_id,
                flow_id=flow_id
            )
            return await result.single() is not None
    
    async def create_flow(
        self,
        flow_id: str,
        source_id: str,
        target_id: str,
        properties: Dict[str, Any]
    ) -> bool:
        """
        Create a data flow with enhanced properties.
        Includes protocol, auth, data classification, etc.
        """
        query = """
        MATCH (s:Component {id: $source_id})
        MATCH (t:Component {id: $target_id})
        MERGE (s)-[f:DATA_FLOW {id: $flow_id}]->(t)
        SET f.name = $name,
            f.protocol = $protocol,
            f.auth = $auth,
            f.data_classification = $data_classification,
            f.crosses_trust_boundary = $crosses_trust_boundary,
            f.encrypted = $encrypted,
            f.created_at = datetime()
        RETURN f
        """
        
        async with self.driver.session() as session:
            result = await session.run(
                query,
                flow_id=flow_id,
                source_id=source_id,
                target_id=target_id,
                name=properties.get("name", properties.get("label", "")),
                protocol=properties.get("protocol", ""),
                auth=properties.get("auth", ""),
                data_classification=properties.get("data_classification", ""),
                crosses_trust_boundary=properties.get("crosses_trust_boundary", False),
                encrypted=properties.get("encrypted", False)
            )
            return await result.single() is not None
    
    async def get_threat_with_relationships(
        self,
        threat_id: str
    ) -> Dict[str, Any]:
        """
        Get a threat with all its relationships:
        - Affected components
        - Impacted flows
        - Mitigations
        """
        query = """
        MATCH (t:Threat {id: $threat_id})
        OPTIONAL MATCH (t)-[:AFFECTS]->(c:Component)
        OPTIONAL MATCH (t)-[:IMPACTS_FLOW]->(f:DATA_FLOW)
        OPTIONAL MATCH (t)-[:HAS_MITIGATION]->(m:Mitigation)
        RETURN t,
               collect(DISTINCT c) as components,
               collect(DISTINCT f) as flows,
               collect(DISTINCT m) as mitigations
        """
        
        async with self.driver.session() as session:
            result = await session.run(query, threat_id=threat_id)
            record = await result.single()
            
            if not record:
                return {}
            
            threat_data = dict(record["t"])
            threat_data["affected_components"] = [
                dict(c) for c in record["components"] if c
            ]
            threat_data["impacted_flows"] = [
                dict(f) for f in record["flows"] if f
            ]
            threat_data["mitigations"] = [
                dict(m) for m in record["mitigations"] if m
            ]
            
            return threat_data
    
    async def get_threats_for_analysis(
        self,
        analysis_id: str
    ) -> List[Dict[str, Any]]:
        """Get all threats for an analysis with relationships"""
        query = """
        MATCH (t:Threat {analysis_id: $analysis_id})
        OPTIONAL MATCH (t)-[:AFFECTS]->(c:Component)
        OPTIONAL MATCH (t)-[:HAS_MITIGATION]->(m:Mitigation)
        RETURN t,
               collect(DISTINCT c.id) as component_ids,
               collect(DISTINCT m) as mitigations
        ORDER BY t.overall_risk DESC
        """
        
        async with self.driver.session() as session:
            result = await session.run(query, analysis_id=analysis_id)
            threats = []
            async for record in result:
                threat_data = dict(record["t"])
                threat_data["affected_component_ids"] = record["component_ids"]
                threat_data["structured_mitigations"] = [
                    dict(m) for m in record["mitigations"] if m
                ]
                threats.append(threat_data)
            return threats
    
    async def sync_threat_from_storage(
        self,
        threat_data: Dict[str, Any]
    ) -> bool:
        """
        Sync a threat from file storage to Neo4j graph.
        Creates threat node and all relationships.
        """
        threat_id = threat_data.get("id")
        if not threat_id:
            return False
        
        # Create/update threat node
        await self.create_threat_enhanced(threat_id, threat_data)
        
        # Link to components
        for comp_id in threat_data.get("affected_component_ids", []):
            await self.link_threat_to_component(threat_id, comp_id)
        
        # Link to flows
        for flow_id in threat_data.get("impacted_flow_ids", []):
            await self.link_threat_to_flow(threat_id, flow_id)
        
        # Create mitigations
        for mit in threat_data.get("structured_mitigations", []):
            mit_id = mit.get("id", f"{threat_id}_mit_{len(threat_data.get('structured_mitigations', []))}")
            await self.create_mitigation(mit_id, threat_id, mit)
        
        logger.info("threat_synced_to_graph", threat_id=threat_id)
        return True
    
    async def get_flow_map_data(
        self,
        project_id: str
    ) -> Dict[str, Any]:
        """
        Get complete flow map data for UI rendering.
        Returns components, flows, and trust boundaries.
        """
        query = """
        MATCH (p:Project {id: $project_id})-[:HAS_COMPONENT]->(c:Component)
        OPTIONAL MATCH (c)-[f:DATA_FLOW]->(c2:Component)
        RETURN collect(DISTINCT c) as components,
               collect(DISTINCT {
                   id: f.id,
                   source: c.id,
                   target: c2.id,
                   name: f.name,
                   protocol: f.protocol,
                   encrypted: f.encrypted,
                   crosses_trust_boundary: f.crosses_trust_boundary
               }) as flows
        """
        
        async with self.driver.session() as session:
            result = await session.run(query, project_id=project_id)
            record = await result.single()
            
            if not record:
                return {"components": [], "flows": [], "trust_boundaries": []}
            
            return {
                "components": [dict(c) for c in record["components"] if c],
                "flows": [f for f in record["flows"] if f.get("id")],
                "trust_boundaries": []  # TODO: Add trust boundary query
            }


