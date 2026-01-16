"""
Qdrant Client for Vector RAG
Manages vector database operations for semantic search
"""

from typing import List, Dict, Any, Optional
import uuid

from qdrant_client import QdrantClient
from qdrant_client.http import models
from qdrant_client.http.models import Distance, VectorParams, PointStruct
import structlog

from app.config import settings
from app.services.embedding_provider import get_embedding_provider

logger = structlog.get_logger()


class QdrantService:
    """
    Qdrant service for vector operations.
    
    Manages:
    - Document embeddings
    - Semantic search
    - Similar threat lookup
    - Context retrieval
    """
    
    def __init__(self):
        self.host = settings.QDRANT_HOST
        self.port = settings.QDRANT_PORT
        self.collection_name = settings.QDRANT_COLLECTION
        self.client: Optional[QdrantClient] = None
        self.embedding_provider = None
        self.vector_size = 384  # Default for all-MiniLM-L6-v2
    
    async def initialize(self):
        """Initialize Qdrant client and collection"""
        try:
            self.client = QdrantClient(host=self.host, port=self.port)
            self.embedding_provider = get_embedding_provider()
            
            # Check if collection exists, create if not
            collections = self.client.get_collections().collections
            collection_names = [c.name for c in collections]
            
            if self.collection_name not in collection_names:
                await self._create_collection()
            
            logger.info("Qdrant connection established", 
                       host=self.host, 
                       port=self.port,
                       collection=self.collection_name)
            
        except Exception as e:
            logger.error("Failed to connect to Qdrant", error=str(e))
            raise
    
    async def _create_collection(self):
        """Create the vector collection"""
        self.client.create_collection(
            collection_name=self.collection_name,
            vectors_config=VectorParams(
                size=self.vector_size,
                distance=Distance.COSINE
            )
        )
        logger.info("Created Qdrant collection", collection=self.collection_name)
    
    async def close(self):
        """Close Qdrant connection"""
        if self.client:
            self.client.close()
            logger.info("Qdrant connection closed")
    
    async def add_documents(
        self,
        project_id: str,
        documents: List[Dict[str, Any]]
    ) -> int:
        """
        Add documents to the vector store.
        
        Args:
            project_id: Project identifier
            documents: List of documents with 'content' and optional 'metadata'
        
        Returns:
            Number of documents added
        """
        points = []
        
        for doc in documents:
            content = doc.get("content", "")
            metadata = doc.get("metadata", {})
            
            # Generate embedding
            embedding = await self.embedding_provider.embed(content)
            
            # Create point
            point_id = str(uuid.uuid4())
            point = PointStruct(
                id=point_id,
                vector=embedding,
                payload={
                    "project_id": project_id,
                    "content": content,
                    "chunk_type": metadata.get("chunk_type", "text"),
                    "source_file": metadata.get("source_file", ""),
                    "page_number": metadata.get("page_number"),
                    **metadata
                }
            )
            points.append(point)
        
        # Upsert in batches
        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i:i + batch_size]
            self.client.upsert(
                collection_name=self.collection_name,
                points=batch
            )
        
        logger.info("Added documents to Qdrant", 
                   project_id=project_id, 
                   count=len(documents))
        
        return len(documents)
    
    async def search(
        self,
        query: str,
        project_id: Optional[str] = None,
        limit: int = 10,
        score_threshold: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Semantic search for relevant documents.
        
        Args:
            query: Search query
            project_id: Optional filter by project
            limit: Maximum results
            score_threshold: Minimum similarity score
        
        Returns:
            List of matching documents with scores
        """
        # Generate query embedding
        query_embedding = await self.embedding_provider.embed(query)
        
        # Build filter
        filter_conditions = []
        if project_id:
            filter_conditions.append(
                models.FieldCondition(
                    key="project_id",
                    match=models.MatchValue(value=project_id)
                )
            )
        
        query_filter = None
        if filter_conditions:
            query_filter = models.Filter(must=filter_conditions)
        
        # Search
        results = self.client.search(
            collection_name=self.collection_name,
            query_vector=query_embedding,
            query_filter=query_filter,
            limit=limit,
            score_threshold=score_threshold
        )
        
        # Format results
        documents = []
        for hit in results:
            documents.append({
                "id": hit.id,
                "score": hit.score,
                "content": hit.payload.get("content", ""),
                "metadata": {
                    k: v for k, v in hit.payload.items() 
                    if k not in ["content", "project_id"]
                },
                "project_id": hit.payload.get("project_id")
            })
        
        return documents
    
    async def search_similar_threats(
        self,
        threat_description: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Search for similar threats in the knowledge base.
        Used for pattern matching and learning from past analyses.
        """
        return await self.search(
            query=f"security threat: {threat_description}",
            limit=limit,
            score_threshold=0.6
        )
    
    async def get_context_for_analysis(
        self,
        project_id: str,
        component_name: str,
        context_type: str = "security"
    ) -> List[Dict[str, Any]]:
        """
        Get relevant context for security analysis.
        
        Args:
            project_id: Project to search
            component_name: Component being analyzed
            context_type: Type of context (security, architecture, data_flow)
        
        Returns:
            Relevant context documents
        """
        query = f"{context_type} analysis for {component_name}"
        
        return await self.search(
            query=query,
            project_id=project_id,
            limit=10,
            score_threshold=0.4
        )
    
    async def delete_project_documents(self, project_id: str) -> bool:
        """Delete all documents for a project"""
        self.client.delete(
            collection_name=self.collection_name,
            points_selector=models.FilterSelector(
                filter=models.Filter(
                    must=[
                        models.FieldCondition(
                            key="project_id",
                            match=models.MatchValue(value=project_id)
                        )
                    ]
                )
            )
        )
        
        logger.info("Deleted project documents from Qdrant", project_id=project_id)
        return True
    
    async def get_collection_info(self) -> Dict[str, Any]:
        """Get collection statistics"""
        info = self.client.get_collection(self.collection_name)
        
        return {
            "name": self.collection_name,
            "vectors_count": info.vectors_count,
            "points_count": info.points_count,
            "status": info.status
        }


