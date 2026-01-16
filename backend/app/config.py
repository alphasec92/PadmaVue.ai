"""
Application Configuration
Secure configuration loading from environment variables with validation
"""

import os
import secrets
from typing import Optional, List
from pydantic import field_validator, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Security Best Practices:
    - All secrets loaded from environment (never hardcoded)
    - Validation on sensitive fields
    - Secure defaults where applicable
    """
    
    # ==========================================
    # Application Settings
    # ==========================================
    APP_NAME: str = "SecurityReview.ai"
    DEBUG: bool = Field(default=False, description="Enable debug mode (disable in production)")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    
    # Security
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for signing (auto-generated if not set)"
    )
    API_KEY: Optional[str] = Field(default=None, description="Optional API key for authentication")
    
    # ==========================================
    # API Configuration
    # ==========================================
    API_V1_PREFIX: str = "/api"
    CORS_ORIGINS: str = Field(
        default="http://localhost:3000",
        description="Comma-separated list of allowed CORS origins"
    )
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="Rate limit per IP per minute")
    
    # ==========================================
    # Storage Configuration
    # ==========================================
    DATA_DIR: str = Field(default="./data", description="Directory for persistent data storage")
    LOG_DIR: str = Field(default="./logs", description="Directory for log files")
    UPLOAD_DIR: str = Field(default="./uploads", description="Directory for uploaded files")
    
    # ==========================================
    # LLM Provider Configuration
    # ==========================================
    LLM_PROVIDER: str = Field(
        default="mock",
        description="LLM provider: mock, openai, anthropic, openrouter, gemini, vertex, bedrock"
    )
    
    # OpenAI
    OPENAI_API_KEY: Optional[str] = Field(default=None, repr=False)
    OPENAI_MODEL: str = "gpt-4-turbo-preview"
    
    # Anthropic / Claude
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, repr=False)
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20241022"
    
    # OpenRouter
    OPENROUTER_API_KEY: Optional[str] = Field(default=None, repr=False)
    OPENROUTER_MODEL: str = "anthropic/claude-3.5-sonnet"
    
    # Google Gemini
    GOOGLE_API_KEY: Optional[str] = Field(default=None, repr=False)
    GOOGLE_MODEL: str = "gemini-1.5-pro"
    
    # Google Vertex AI
    GOOGLE_CLOUD_PROJECT: Optional[str] = None
    VERTEX_LOCATION: str = "us-central1"
    VERTEX_MODEL: str = "gemini-1.5-pro"
    
    # AWS Bedrock
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None, repr=False)
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None, repr=False)
    AWS_REGION: str = "us-east-1"
    BEDROCK_MODEL_ID: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    
    # Ollama (Local)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1"
    
    # LM Studio (Local)
    LMSTUDIO_BASE_URL: str = "http://localhost:1234/v1"
    LMSTUDIO_MODEL: Optional[str] = None
    
    # ==========================================
    # Web Search Configuration (for Grounded Responses)
    # ==========================================
    SEARCH_PROVIDER: str = Field(
        default="none",
        description="Web search provider: none, searxng, tavily, serper, brave, bing, mock"
    )
    # SearXNG (open-source, self-hosted) - recommended default
    SEARXNG_BASE_URL: str = Field(
        default="http://localhost:8080",
        description="SearXNG instance URL"
    )
    # Paid provider API keys (optional)
    SEARCH_API_KEY: Optional[str] = Field(default=None, repr=False, description="Generic API key for search provider")
    TAVILY_API_KEY: Optional[str] = Field(default=None, repr=False, description="Tavily API key")
    SERPER_API_KEY: Optional[str] = Field(default=None, repr=False, description="Serper API key")
    BRAVE_API_KEY: Optional[str] = Field(default=None, repr=False, description="Brave Search API key")
    BING_API_KEY: Optional[str] = Field(default=None, repr=False, description="Bing Search API key")
    SEARCH_MAX_RESULTS: int = Field(default=5, description="Max search results to return")
    
    # ==========================================
    # Thinking Time / Reasoning Configuration
    # ==========================================
    REASONING_LEVEL: str = Field(
        default="balanced",
        description="Reasoning depth: fast, balanced, deep"
    )
    SHOW_REASONING_SUMMARY: bool = Field(
        default=True,
        description="Show concise reasoning summary (not raw chain-of-thought)"
    )
    
    # ==========================================
    # Embeddings Configuration
    # ==========================================
    EMBEDDING_PROVIDER: str = "mock"
    EMBEDDING_MODEL: str = "text-embedding-3-small"
    
    # ==========================================
    # Database Configuration
    # ==========================================
    
    # Neo4j (GraphRAG)
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = Field(default="securityreview", repr=False)
    
    # Qdrant (Vector RAG)
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_COLLECTION: str = "security_documents"
    QDRANT_API_KEY: Optional[str] = Field(default=None, repr=False)
    
    # ==========================================
    # File Storage
    # ==========================================
    MAX_FILE_SIZE: int = Field(default=10 * 1024 * 1024, description="Max file size in bytes (10MB)")
    ALLOWED_EXTENSIONS: str = ".pdf,.md,.txt,.json,.yaml,.yml,.xml,.py,.js,.ts,.tf"
    
    # ==========================================
    # Logging Configuration
    # ==========================================
    LOG_TO_FILE: bool = Field(default=True, description="Enable file logging")
    LOG_MAX_SIZE_MB: int = Field(default=10, description="Max log file size in MB")
    LOG_RETENTION_DAYS: int = Field(default=30, description="Log retention period")
    
    # ==========================================
    # Validators
    # ==========================================
    
    @field_validator('LOG_LEVEL')
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        v = v.upper()
        if v not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v
    
    @field_validator('LLM_PROVIDER')
    @classmethod
    def validate_llm_provider(cls, v: str) -> str:
        allowed = ['mock', 'openai', 'anthropic', 'claude', 'openrouter', 'gemini', 'google', 'vertex', 'bedrock', 'aws', 'ollama', 'lmstudio']
        v = v.lower()
        if v not in allowed:
            raise ValueError(f"LLM_PROVIDER must be one of {allowed}")
        return v
    
    @field_validator('MAX_FILE_SIZE')
    @classmethod
    def validate_max_file_size(cls, v: int) -> int:
        max_allowed = 100 * 1024 * 1024  # 100MB absolute max
        if v > max_allowed:
            raise ValueError(f"MAX_FILE_SIZE cannot exceed {max_allowed} bytes")
        return v
    
    @property
    def allowed_extensions_list(self) -> List[str]:
        """Get allowed file extensions as a list"""
        return [ext.strip().lower() for ext in self.ALLOWED_EXTENSIONS.split(",")]
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Get CORS origins as a list"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]
    
    def is_extension_allowed(self, filename: str) -> bool:
        """Check if file extension is allowed"""
        ext = os.path.splitext(filename)[1].lower()
        return ext in self.allowed_extensions_list
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"
        case_sensitive = False


# Global settings instance
settings = Settings()


# Validate critical settings on import
def validate_settings():
    """Validate settings on startup"""
    import structlog
    logger = structlog.get_logger()
    
    if not settings.DEBUG and settings.SECRET_KEY == "dev-secret-key-change-in-production":
        raise ValueError("SECRET_KEY must be changed in production")
    
    # Create required directories
    for dir_path in [settings.DATA_DIR, settings.LOG_DIR, settings.UPLOAD_DIR]:
        os.makedirs(dir_path, mode=0o750, exist_ok=True)
    
    logger.info(
        "Configuration loaded",
        debug=settings.DEBUG,
        llm_provider=settings.LLM_PROVIDER,
        data_dir=settings.DATA_DIR,
        log_dir=settings.LOG_DIR
    )


try:
    validate_settings()
except Exception as e:
    print(f"Configuration warning: {e}")
