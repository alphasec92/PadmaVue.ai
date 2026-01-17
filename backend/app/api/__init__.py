"""
API Routes for PadmaVue.ai
"""

from app.api import ingest, analyze, dfd, report, settings, threats, architect, export, mcp

__all__ = [
    "ingest", 
    "analyze", 
    "dfd", 
    "report", 
    "settings", 
    "threats", 
    "architect", 
    "export", 
    "mcp"
]
