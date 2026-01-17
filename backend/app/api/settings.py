"""
Settings API Endpoints
Configure LLM providers and application settings
"""

from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from app.config import settings
from app.services.llm_provider import (
    get_provider_info,
    get_llm_provider,
    OllamaProvider,
    PROVIDER_INFO,
)
from app.core.logging import audit_logger

logger = structlog.get_logger()
router = APIRouter()


# ===========================================
# Models
# ===========================================

class ProviderConfig(BaseModel):
    """LLM Provider configuration"""
    provider: str
    api_key: Optional[str] = Field(default=None, description="API key (for cloud providers)")
    model: Optional[str] = Field(default=None, description="Model name/ID")
    base_url: Optional[str] = Field(default=None, description="Base URL (for local providers)")
    project_id: Optional[str] = Field(default=None, description="Project ID (for Vertex)")
    region: Optional[str] = Field(default=None, description="Region (for AWS/Vertex)")
    access_key: Optional[str] = Field(default=None, description="AWS access key")
    secret_key: Optional[str] = Field(default=None, description="AWS secret key")
    location: Optional[str] = Field(default=None, description="Location (for Vertex)")


class ProviderInfo(BaseModel):
    """Provider information for UI"""
    id: str
    name: str
    description: str
    requires_api_key: bool
    requires_local: bool
    default_model: str
    available_models: List[str]
    config_fields: List[Dict[str, Any]]


class TestResult(BaseModel):
    """Result of testing a provider configuration"""
    success: bool
    message: str
    latency_ms: Optional[float] = None
    model_used: Optional[str] = None


class CurrentSettings(BaseModel):
    """Current application settings"""
    llm_provider: str
    llm_model: Optional[str]
    debug: bool
    log_level: str


# In-memory settings override (for runtime configuration)
_runtime_config: Dict[str, Any] = {}


# ===========================================
# Endpoints
# ===========================================

@router.get("/providers", response_model=List[ProviderInfo])
async def list_providers():
    """
    List all available LLM providers with their configuration options.
    
    Returns information needed to render the settings UI.
    """
    return get_provider_info()


@router.get("/providers/{provider_id}")
async def get_provider(provider_id: str):
    """Get detailed information about a specific provider"""
    if provider_id not in PROVIDER_INFO:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    info = PROVIDER_INFO[provider_id]
    return {
        "id": info.id,
        "name": info.name,
        "description": info.description,
        "requires_api_key": info.requires_api_key,
        "requires_local": info.requires_local,
        "default_model": info.default_model,
        "available_models": info.available_models,
        "config_fields": info.config_fields
    }


@router.get("/current")
async def get_current_settings():
    """Get current application settings"""
    # Check if configured via runtime config OR environment settings
    provider = _runtime_config.get("provider") or settings.LLM_PROVIDER
    is_configured = bool(provider and provider != "none")
    
    return {
        "llm_provider": provider or "none",
        "llm_model": _runtime_config.get("model") or getattr(settings, f"{provider.upper()}_MODEL", None) if provider else None,
        "debug": settings.DEBUG,
        "log_level": settings.LOG_LEVEL,
        "is_configured": is_configured
    }


@router.post("/configure")
async def configure_provider(config: ProviderConfig):
    """
    Configure the LLM provider for the application.
    
    This sets the provider at runtime (does not persist to .env file).
    The configuration is stored in memory and used for subsequent requests.
    """
    global _runtime_config
    
    # Validate provider
    if config.provider not in PROVIDER_INFO:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {config.provider}")
    
    provider_info = PROVIDER_INFO[config.provider]
    
    # Validate required fields
    if provider_info.requires_api_key and not config.api_key:
        raise HTTPException(status_code=400, detail="API key is required for this provider")
    
    # Store configuration
    _runtime_config = {
        "provider": config.provider,
        "api_key": config.api_key,
        "model": config.model or provider_info.default_model,
        "base_url": config.base_url,
        "project_id": config.project_id,
        "region": config.region,
        "access_key": config.access_key,
        "secret_key": config.secret_key,
        "location": config.location,
    }
    
    # Audit log
    audit_logger.log_access(
        user_id="api",
        resource="settings",
        action="configure_provider",
        success=True,
        provider=config.provider
    )
    
    logger.info("LLM provider configured",
               provider=config.provider,
               model=config.model)
    
    return {
        "status": "configured",
        "provider": config.provider,
        "model": config.model or provider_info.default_model,
        "message": f"Successfully configured {provider_info.name}"
    }


@router.post("/test", response_model=TestResult)
async def test_provider(config: ProviderConfig):
    """
    Test an LLM provider configuration.
    
    Sends a simple test prompt to verify the provider is working.
    """
    import time
    
    try:
        # Create provider with config
        provider = get_llm_provider({
            "provider": config.provider,
            "api_key": config.api_key,
            "model": config.model,
            "base_url": config.base_url,
            "project_id": config.project_id,
            "region": config.region,
            "access_key": config.access_key,
            "secret_key": config.secret_key,
            "location": config.location,
        })
        
        # Test with a simple prompt
        start_time = time.time()
        response = await provider.generate(
            prompt="Say 'Hello, PadmaVue.ai!' in exactly those words.",
            max_tokens=50
        )
        latency_ms = (time.time() - start_time) * 1000
        
        if response and len(response) > 0:
            return TestResult(
                success=True,
                message="Provider is working correctly",
                latency_ms=round(latency_ms, 2),
                model_used=config.model or PROVIDER_INFO.get(config.provider, {}).default_model
            )
        else:
            return TestResult(
                success=False,
                message="Provider returned empty response"
            )
            
    except Exception as e:
        logger.error("Provider test failed", error=str(e), provider=config.provider)
        return TestResult(
            success=False,
            message=f"Connection failed: {str(e)}"
        )


@router.get("/ollama/models")
async def list_ollama_models(base_url: str = "http://localhost:11434"):
    """List available models from Ollama"""
    try:
        provider = OllamaProvider(base_url=base_url)
        models = await provider.list_models()
        return {
            "available": True,
            "models": models,
            "count": len(models)
        }
    except Exception as e:
        return {
            "available": False,
            "models": [],
            "error": str(e)
        }


@router.post("/reset")
async def reset_settings():
    """Reset to default settings (from environment variables)"""
    global _runtime_config
    _runtime_config = {}
    
    logger.info("Settings reset to defaults")
    
    return {
        "status": "reset",
        "message": "Settings reset to environment defaults",
        "current_provider": settings.LLM_PROVIDER
    }


def get_runtime_config() -> Dict[str, Any]:
    """Get current runtime configuration (for use by other modules)"""
    if _runtime_config:
        return _runtime_config
    return None


