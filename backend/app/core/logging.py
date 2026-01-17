"""
Logging - Structured logging with file output and sensitive data masking
"""

import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import structlog
from structlog.processors import JSONRenderer, TimeStamper, add_log_level

from app.config import settings

# Log directory
LOG_DIR = Path(settings.LOG_DIR)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Sensitive keys to mask
SENSITIVE_KEYS = frozenset({'password', 'secret', 'api_key', 'token', 'authorization', 'credentials', 'private_key'})


# ===========================================
# Processors
# ===========================================

def add_context(_, __, event_dict):
    """Add app context"""
    event_dict.update(app="PadmaVue.ai", version="1.0.0")
    return event_dict


def mask_sensitive(_, __, event_dict):
    """Mask sensitive data in logs"""
    def mask(d):
        if not isinstance(d, dict):
            return d
        return {k: "***" if any(s in k.lower() for s in SENSITIVE_KEYS) else (mask(v) if isinstance(v, dict) else v) for k, v in d.items()}
    return mask(event_dict)


# ===========================================
# Rotating File Handler
# ===========================================

class DailyFileHandler(logging.FileHandler):
    """Daily rotating JSON file handler"""
    
    def __init__(self, name: str, max_mb: int = 10):
        self.base_name = name
        self.max_bytes = max_mb * 1024 * 1024
        super().__init__(self._filename(), mode='a', encoding='utf-8')
    
    def _filename(self) -> str:
        return str(LOG_DIR / f"{self.base_name}_{datetime.now():%Y-%m-%d}.log")
    
    def emit(self, record):
        try:
            if self.stream and os.path.getsize(self.baseFilename) > self.max_bytes:
                self.close()
                self.baseFilename = self._filename()
                self.stream = self._open()
        except OSError:
            pass
        super().emit(record)


# ===========================================
# Configure Logging
# ===========================================

def configure_logging():
    """Setup structured logging"""
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    handlers = [
        logging.StreamHandler(sys.stdout),
        DailyFileHandler("app"),
        DailyFileHandler("error"),
    ]
    handlers[2].setLevel(logging.ERROR)
    
    logging.basicConfig(format="%(message)s", level=level, handlers=handlers)
    
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            add_log_level,
            add_context,
            mask_sensitive,
            structlog.stdlib.PositionalArgumentsFormatter(),
            TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            JSONRenderer()
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ===========================================
# Specialized Loggers
# ===========================================

class AuditLogger:
    """Security audit logger"""
    def __init__(self):
        self._log = structlog.get_logger("audit")
        self._handler = DailyFileHandler("audit")
    
    def log_access(self, user_id: str, resource: str, action: str, success: bool, **kw):
        self._log.info("access", user_id=user_id, resource=resource, action=action, success=success, **kw)
    
    def log_auth(self, user_id: str, event: str, success: bool, **kw):
        self._log.info("auth", user_id=user_id, event=event, success=success, **kw)
    
    def log_data_access(self, user_id: str, data_type: str, record_id: str, **kw):
        self._log.info("data", user_id=user_id, data_type=data_type, record_id=record_id, **kw)


class AILogger:
    """AI/LLM interaction logger"""
    def __init__(self):
        self._log = structlog.get_logger("ai")
        self._handler = DailyFileHandler("ai_interactions")
    
    def log_request(self, request_id: str, provider: str, model: str, **kw):
        self._log.info("request", request_id=request_id, provider=provider, model=model, **kw)
    
    def log_response(self, request_id: str, provider: str, latency_ms: float = 0, success: bool = True, **kw):
        self._log.info("response", request_id=request_id, provider=provider, latency_ms=latency_ms, success=success, **kw)
    
    def log_agent_action(self, agent_name: str, action: str, project_id: str, **kw):
        self._log.info("agent", agent_name=agent_name, action=action, project_id=project_id, **kw)


# Initialize on import
configure_logging()
logger = structlog.get_logger()
audit_logger = AuditLogger()
ai_logger = AILogger()

# Backward compatibility
AIInteractionLogger = AILogger
