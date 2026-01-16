"""
Embedding Provider
Manages text embedding generation for vector search
"""

from typing import List, Optional
from abc import ABC, abstractmethod

import structlog

from app.config import settings

logger = structlog.get_logger()


class EmbeddingProvider(ABC):
    """Abstract base class for embedding providers"""
    
    @abstractmethod
    async def embed(self, text: str) -> List[float]:
        """Generate embedding for a single text"""
        pass
    
    @abstractmethod
    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts"""
        pass


class MockEmbeddingProvider(EmbeddingProvider):
    """
    Mock embedding provider for offline development.
    Generates deterministic pseudo-embeddings based on text hash.
    """
    
    def __init__(self, vector_size: int = 384):
        self.vector_size = vector_size
        logger.info("Initialized MockEmbeddingProvider", vector_size=vector_size)
    
    async def embed(self, text: str) -> List[float]:
        """Generate a deterministic mock embedding"""
        import hashlib
        
        # Create deterministic hash-based embedding
        hash_obj = hashlib.sha256(text.encode())
        hash_bytes = hash_obj.digest()
        
        # Expand hash to vector size
        embedding = []
        for i in range(self.vector_size):
            byte_idx = i % len(hash_bytes)
            # Normalize to [-1, 1]
            value = (hash_bytes[byte_idx] - 128) / 128.0
            embedding.append(value)
        
        # Normalize vector
        magnitude = sum(x**2 for x in embedding) ** 0.5
        if magnitude > 0:
            embedding = [x / magnitude for x in embedding]
        
        return embedding
    
    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate mock embeddings for batch"""
        return [await self.embed(text) for text in texts]


class SentenceTransformerProvider(EmbeddingProvider):
    """
    Sentence Transformers embedding provider.
    Uses local models for embedding generation.
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self._load_model()
    
    def _load_model(self):
        """Lazy load the model"""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info("Loaded SentenceTransformer model", model=self.model_name)
        except Exception as e:
            logger.error("Failed to load SentenceTransformer", error=str(e))
            raise
    
    async def embed(self, text: str) -> List[float]:
        """Generate embedding using sentence transformers"""
        if self.model is None:
            self._load_model()
        
        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()
    
    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate batch embeddings"""
        if self.model is None:
            self._load_model()
        
        embeddings = self.model.encode(texts, convert_to_numpy=True)
        return [emb.tolist() for emb in embeddings]


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """
    OpenAI embedding provider.
    Uses OpenAI API for embedding generation.
    """
    
    def __init__(self, model: str = "text-embedding-3-small"):
        self.model = model
        self.client = None
        self._init_client()
    
    def _init_client(self):
        """Initialize OpenAI client"""
        try:
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(api_key=settings.openai_api_key)
            logger.info("Initialized OpenAI embedding provider", model=self.model)
        except Exception as e:
            logger.error("Failed to initialize OpenAI client", error=str(e))
            raise
    
    async def embed(self, text: str) -> List[float]:
        """Generate embedding using OpenAI API"""
        response = await self.client.embeddings.create(
            model=self.model,
            input=text
        )
        return response.data[0].embedding
    
    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate batch embeddings using OpenAI API"""
        response = await self.client.embeddings.create(
            model=self.model,
            input=texts
        )
        return [item.embedding for item in response.data]


def get_embedding_provider() -> EmbeddingProvider:
    """
    Factory function to get the configured embedding provider.
    """
    provider = settings.embedding_provider.lower()
    
    if provider == "mock":
        return MockEmbeddingProvider()
    
    elif provider == "sentence-transformers":
        try:
            return SentenceTransformerProvider(settings.embedding_model)
        except Exception:
            logger.warning("Falling back to mock embedding provider")
            return MockEmbeddingProvider()
    
    elif provider == "openai":
        if not settings.openai_api_key:
            logger.warning("OpenAI API key not set, falling back to mock")
            return MockEmbeddingProvider()
        return OpenAIEmbeddingProvider()
    
    else:
        logger.warning(f"Unknown embedding provider: {provider}, using mock")
        return MockEmbeddingProvider()


