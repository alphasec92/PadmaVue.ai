"""
PadmaVue.ai - Main FastAPI Application
AI-Powered Security Review Platform

Security-hardened with:
- Rate limiting
- Security headers
- Input validation
- Request ID tracking
- Structured logging
"""

import os
import uuid
import time
import secrets
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.config import settings as app_settings
from app.api import ingest, analyze, dfd, report, settings as settings_api, threats, architect, export, mcp
from app.services.neo4j_client import Neo4jClient
from app.services.qdrant_client import QdrantService
from app.services.mcp_client import mcp_manager

# Configure structured logging with security-safe output
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


# ============================================
# Security Middleware
# ============================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # HSTS - enforce HTTPS (1 year, include subdomains)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Content Security Policy - prevents XSS and injection attacks
        # Note: 'unsafe-inline' needed for React/Next.js inline styles and scripts
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self' http://localhost:* ws://localhost:*; "
            "frame-ancestors 'none'"
        )
        
        # Cache control for API responses
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID for tracing"""
    
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        
        # Bind request ID to logger context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting"""
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.request_counts: Dict[str, list] = defaultdict(list)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP, considering proxies"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    def _cleanup_old_requests(self, client_ip: str, current_time: float):
        """Remove requests older than 1 minute"""
        cutoff = current_time - 60
        self.request_counts[client_ip] = [
            t for t in self.request_counts[client_ip] if t > cutoff
        ]
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks and status/polling endpoints
        skip_paths = ["/health", "/", "/docs", "/redoc", "/openapi.json"]
        # Also skip lightweight status/polling endpoints to avoid rate limiting frontend polls
        skip_suffixes = ["/status", "/providers"]
        
        if request.url.path in skip_paths:
            return await call_next(request)
        
        # Skip status polling endpoints (lightweight GET requests)
        if request.method == "GET" and any(request.url.path.endswith(suffix) for suffix in skip_suffixes):
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        current_time = time.time()
        
        self._cleanup_old_requests(client_ip, current_time)
        
        if len(self.request_counts[client_ip]) >= self.requests_per_minute:
            logger.warning("Rate limit exceeded", client_ip=client_ip)
            return JSONResponse(
                status_code=429,
                content={
                    "error": True,
                    "message": "Too many requests. Please try again later.",
                    "status_code": 429
                },
                headers={"Retry-After": "60"}
            )
        
        self.request_counts[client_ip].append(current_time)
        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with timing"""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Don't log sensitive data
        safe_path = request.url.path
        method = request.method
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        
        logger.info(
            "Request processed",
            method=method,
            path=safe_path,
            status_code=response.status_code,
            process_time_ms=round(process_time * 1000, 2)
        )
        
        response.headers["X-Process-Time"] = str(round(process_time * 1000, 2))
        
        return response


# ============================================
# Application State
# ============================================

app_state: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown"""
    # Startup
    logger.info(
        "Starting PadmaVue.ai Backend",
        version="1.0.0",
        debug=app_settings.DEBUG,
        llm_provider=app_settings.LLM_PROVIDER
    )
    
    # Create upload directory with secure permissions
    os.makedirs(app_settings.UPLOAD_DIR, mode=0o750, exist_ok=True)
    
    # Initialize Neo4j connection
    try:
        neo4j_client = Neo4jClient()
        await neo4j_client.connect()
        app_state["neo4j"] = neo4j_client
        logger.info("Neo4j connection established")
    except Exception as e:
        logger.warning("Neo4j connection failed - running in degraded mode", error=str(e))
        app_state["neo4j"] = None
    
    # Initialize Qdrant connection
    try:
        qdrant_service = QdrantService()
        await qdrant_service.initialize()
        app_state["qdrant"] = qdrant_service
        logger.info("Qdrant connection established")
    except Exception as e:
        logger.warning("Qdrant connection failed - running in degraded mode", error=str(e))
        app_state["qdrant"] = None
    
    # Initialize MCP server connections
    try:
        await mcp_manager.connect_all()
        app_state["mcp"] = mcp_manager
        logger.info("MCP client initialized", servers_count=len(mcp_manager.servers))
    except Exception as e:
        logger.warning("MCP client initialization failed", error=str(e))
        app_state["mcp"] = None
    
    yield
    
    # Shutdown
    logger.info("Shutting down PadmaVue.ai Backend")
    
    if app_state.get("neo4j"):
        await app_state["neo4j"].close()
    
    if app_state.get("qdrant"):
        await app_state["qdrant"].close()
    
    if app_state.get("mcp"):
        await mcp_manager.disconnect_all()


# ============================================
# Create FastAPI Application
# ============================================

app = FastAPI(
    title="PadmaVue.ai API",
    description="AI-Powered Security Review Platform - Threat Modeling, Compliance Mapping, and DevSecOps",
    version="1.0.0",
    docs_url="/docs" if app_settings.DEBUG else None,  # Disable docs in production
    redoc_url="/redoc" if app_settings.DEBUG else None,
    openapi_url="/openapi.json" if app_settings.DEBUG else None,
    lifespan=lifespan
)

# ============================================
# Add Middleware (order matters - first added is outermost)
# ============================================

# Request logging (outermost)
app.add_middleware(RequestLoggingMiddleware)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# Request ID tracking
app.add_middleware(RequestIDMiddleware)

# Rate limiting
app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=app_settings.RATE_LIMIT_PER_MINUTE if hasattr(app_settings, 'RATE_LIMIT_PER_MINUTE') else 60
)

# CORS - configured securely
cors_origins = [origin.strip() for origin in app_settings.CORS_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Explicit methods
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],  # Explicit headers
    expose_headers=["X-Request-ID", "X-Process-Time"],
    max_age=600,  # Cache preflight for 10 minutes
)


# ============================================
# Routes
# ============================================

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for container orchestration"""
    neo4j_status = "connected" if app_state.get("neo4j") else "disconnected"
    qdrant_status = "connected" if app_state.get("qdrant") else "disconnected"
    mcp_status = {
        "status": "initialized" if app_state.get("mcp") else "not_initialized",
        "servers_connected": len(mcp_manager.servers) if app_state.get("mcp") else 0,
        "tools_available": len(mcp_manager.get_all_tools()) if app_state.get("mcp") else 0,
    }
    
    return {
        "status": "healthy",
        "version": "1.0.0",
        "services": {
            "neo4j": neo4j_status,
            "qdrant": qdrant_status,
            "mcp": mcp_status
        }
    }


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "PadmaVue.ai API",
        "version": "1.0.0",
        "description": "AI-Powered Security Review Platform",
        "docs": "/docs" if app_settings.DEBUG else "Disabled in production",
        "health": "/health"
    }


# Include API routers with prefix
app.include_router(ingest.router, prefix="/api/ingest", tags=["Ingestion"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["Analysis"])
app.include_router(dfd.router, prefix="/api/dfd", tags=["DFD"])
app.include_router(report.router, prefix="/api/report", tags=["Reports"])
app.include_router(settings_api.router, prefix="/api/settings", tags=["Settings"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threats"])
app.include_router(architect.router, prefix="/api/architect", tags=["Security Architect"])
app.include_router(export.router, prefix="/api/export", tags=["Export"])
app.include_router(mcp.router, prefix="/api/mcp", tags=["MCP Servers"])

# Intelligent AI Chat-based Architect
from app.api import architect_chat
app.include_router(architect_chat.router, prefix="/api/architect-chat", tags=["AI Security Architect"])


# ============================================
# Exception Handlers
# ============================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions securely"""
    # Don't expose internal details in production
    message = exc.detail
    if not app_settings.DEBUG and exc.status_code >= 500:
        message = "Internal server error"
    
    logger.warning(
        "HTTP exception",
        status_code=exc.status_code,
        path=request.url.path
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": message,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions securely"""
    # Log the full error but don't expose to client
    logger.error(
        "Unhandled exception",
        error=str(exc),
        path=request.url.path,
        exc_info=True
    )
    
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error",
            "status_code": 500
        }
    )


# ============================================
# Dependencies
# ============================================

def get_app_state() -> Dict[str, Any]:
    """Get application state with service connections"""
    return app_state


def verify_api_key(request: Request) -> Optional[str]:
    """
    Verify API key if configured.
    Returns the API key or None if not required/provided.
    """
    if not hasattr(app_settings, 'API_KEY') or not app_settings.API_KEY:
        return None
    
    api_key = request.headers.get("X-API-Key")
    if not api_key or not secrets.compare_digest(api_key, app_settings.API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    
    return api_key


# ============================================
# Main Entry Point
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=app_settings.DEBUG,
        log_level="info",
        access_log=True,
        # Security: Limit request size
        limit_concurrency=100,
        limit_max_requests=10000,
    )
