"""
OWASP Reference Registry - Single Source of Truth

This module provides a centralized registry of OWASP security reference documents.
These are reference pointers (metadata only) used in reports for external citations.

NO content from these URLs is embedded - only metadata (title, URL, short description).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class ReferenceCategory(str, Enum):
    """Categories of OWASP references"""
    WEB_APP = "web_application"
    API = "api_security"
    LLM_AI = "llm_ai"
    AGENTIC_AI = "agentic_ai"
    GENAI_GENERAL = "genai_general"
    RED_TEAM = "red_team"


@dataclass
class OWASPReference:
    """
    OWASP Reference Document Metadata
    
    Contains only pointers to external resources - no embedded content.
    Used for citation purposes in security reports.
    """
    id: str
    title: str
    url: str
    short_description: str
    category: ReferenceCategory
    year: Optional[int] = None
    version: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "title": self.title,
            "url": self.url,
            "short_description": self.short_description,
            "category": self.category.value,
            "year": self.year,
            "version": self.version
        }
    
    def to_citation(self) -> str:
        """Format as a citation string"""
        year_str = f" ({self.year})" if self.year else ""
        return f"{self.title}{year_str}"


# ===========================================
# OWASP Reference Registry
# ===========================================

OWASP_REFERENCES: Dict[str, OWASPReference] = {
    # Web Application Security
    "OWASP_TOP10_2025": OWASPReference(
        id="OWASP_TOP10_2025",
        title="OWASP Top 10:2025",
        url="https://owasp.org/Top10/2025/",
        short_description="The top 10 most critical web application security risks",
        category=ReferenceCategory.WEB_APP,
        year=2025,
        version="2025",
        keywords=["web", "application", "injection", "auth", "access control", "cryptographic", "ssrf", "misconfiguration"]
    ),
    
    # LLM AI Security
    "OWASP_LLM_TOP10": OWASPReference(
        id="OWASP_LLM_TOP10",
        title="OWASP Top 10 for LLM Applications",
        url="https://genai.owasp.org/llm-top-10/",
        short_description="Security risks for Large Language Model applications",
        category=ReferenceCategory.LLM_AI,
        year=2025,
        version="2025",
        keywords=["llm", "prompt injection", "data leakage", "model", "ai", "gpt", "chatbot", "rag", "embedding"]
    ),
    
    # Agentic AI Security
    "OWASP_AGENTIC_THREATS": OWASPReference(
        id="OWASP_AGENTIC_THREATS",
        title="Agentic AI Threats and Mitigations",
        url="https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
        short_description="Threat landscape for autonomous AI agent systems",
        category=ReferenceCategory.AGENTIC_AI,
        year=2025,
        keywords=["agentic", "agent", "autonomous", "tool use", "mcp", "function calling", "memory", "multi-agent"]
    ),
    
    "OWASP_AGENTIC_TOP10_2026": OWASPReference(
        id="OWASP_AGENTIC_TOP10_2026",
        title="OWASP Top 10 for Agentic Applications (2026)",
        url="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        short_description="Top 10 security risks for agentic AI applications",
        category=ReferenceCategory.AGENTIC_AI,
        year=2026,
        version="2026",
        keywords=["agentic", "agent", "autonomous", "top 10", "tool abuse", "goal hijacking"]
    ),
    
    # GenAI General Resources
    "OWASP_GENAI_INITIATIVES": OWASPReference(
        id="OWASP_GENAI_INITIATIVES",
        title="OWASP GenAI Security Initiatives",
        url="https://genai.owasp.org/initiatives/",
        short_description="Overview of OWASP Generative AI security initiatives",
        category=ReferenceCategory.GENAI_GENERAL,
        year=2025,
        keywords=["genai", "generative ai", "initiatives", "projects"]
    ),
    
    # Red Teaming
    "OWASP_GENAI_REDTEAM": OWASPReference(
        id="OWASP_GENAI_REDTEAM",
        title="GenAI Red Teaming Guide",
        url="https://genai.owasp.org/resource/genai-red-teaming-guide/",
        short_description="Guide for red teaming Generative AI systems",
        category=ReferenceCategory.RED_TEAM,
        year=2025,
        keywords=["red team", "testing", "adversarial", "penetration", "security testing"]
    ),
    
    # API Security (for completeness)
    "OWASP_API_TOP10_2023": OWASPReference(
        id="OWASP_API_TOP10_2023",
        title="OWASP API Security Top 10",
        url="https://owasp.org/API-Security/editions/2023/en/0x00-header/",
        short_description="Top 10 API security risks",
        category=ReferenceCategory.API,
        year=2023,
        version="2023",
        keywords=["api", "rest", "bola", "authentication", "authorization", "graphql"]
    ),
}


class ReferenceRegistry:
    """
    Central registry for accessing OWASP references.
    
    Usage:
        registry = ReferenceRegistry()
        ref = registry.get("OWASP_TOP10_2025")
        all_llm_refs = registry.get_by_category(ReferenceCategory.LLM_AI)
    """
    
    def __init__(self):
        self._references = OWASP_REFERENCES
    
    def get(self, ref_id: str) -> Optional[OWASPReference]:
        """Get a reference by ID"""
        return self._references.get(ref_id)
    
    def get_many(self, ref_ids: List[str]) -> List[OWASPReference]:
        """Get multiple references by IDs"""
        return [ref for ref_id in ref_ids if (ref := self._references.get(ref_id))]
    
    def get_by_category(self, category: ReferenceCategory) -> List[OWASPReference]:
        """Get all references in a category"""
        return [ref for ref in self._references.values() if ref.category == category]
    
    def get_all(self) -> List[OWASPReference]:
        """Get all references"""
        return list(self._references.values())
    
    def get_all_ids(self) -> List[str]:
        """Get all reference IDs"""
        return list(self._references.keys())
    
    def search_by_keywords(self, keywords: List[str]) -> List[OWASPReference]:
        """Find references matching any of the given keywords"""
        keywords_lower = [kw.lower() for kw in keywords]
        matches = []
        for ref in self._references.values():
            if any(kw in ref.keywords for kw in keywords_lower):
                matches.append(ref)
        return matches
    
    def to_dict(self, ref_ids: Optional[List[str]] = None) -> Dict[str, Dict]:
        """
        Convert references to dictionary format.
        If ref_ids provided, only include those references.
        """
        if ref_ids:
            refs = self.get_many(ref_ids)
        else:
            refs = self.get_all()
        return {ref.id: ref.to_dict() for ref in refs}
    
    def format_for_report(self, ref_ids: List[str]) -> List[Dict]:
        """
        Format references for inclusion in a report.
        Returns a list suitable for report rendering.
        """
        refs = self.get_many(ref_ids)
        return [
            {
                "id": ref.id,
                "title": ref.title,
                "url": ref.url,
                "description": ref.short_description
            }
            for ref in refs
        ]


# Global singleton instance
_registry = None


def get_reference_registry() -> ReferenceRegistry:
    """Get the global reference registry singleton"""
    global _registry
    if _registry is None:
        _registry = ReferenceRegistry()
    return _registry


# Convenience functions
def get_reference(ref_id: str) -> Optional[OWASPReference]:
    """Get a single reference by ID"""
    return get_reference_registry().get(ref_id)


def get_references(ref_ids: List[str]) -> List[OWASPReference]:
    """Get multiple references by IDs"""
    return get_reference_registry().get_many(ref_ids)


def format_references_for_report(ref_ids: List[str]) -> List[Dict]:
    """Format references for inclusion in reports"""
    return get_reference_registry().format_for_report(ref_ids)
