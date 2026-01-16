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


