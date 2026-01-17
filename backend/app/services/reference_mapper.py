"""
Reference Mapper Service

Maps security findings to OWASP references using deterministic rules.
NO hallucination - references are ONLY assigned based on explicit evidence in finding fields.

Mapping Rules:
- Based on finding.category, tags, type, STRIDE category, detection reason
- If uncertain, DO NOT map (conservative approach)
- Unmapped findings are flagged for manual review
"""

from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass, field
import structlog

from app.core.references import (
    get_reference_registry,
    ReferenceCategory,
    OWASPReference,
    format_references_for_report
)

logger = structlog.get_logger(__name__)


@dataclass
class MappingResult:
    """Result of reference mapping for a finding"""
    finding_id: str
    reference_ids: List[str]
    mapping_reasons: List[str]  # Why each reference was mapped
    confidence: str  # "high", "medium", "low"
    unmapped_reason: Optional[str] = None  # If no references could be mapped
    
    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "reference_ids": self.reference_ids,
            "mapping_reasons": self.mapping_reasons,
            "confidence": self.confidence,
            "unmapped_reason": self.unmapped_reason
        }


# ===========================================
# Deterministic Keyword Mappings
# ===========================================

# Keywords that indicate LLM/AI involvement
LLM_AI_KEYWORDS = {
    "prompt injection", "llm", "large language model", "gpt", "chatbot", "ai", 
    "artificial intelligence", "machine learning", "ml", "model", "neural network",
    "embedding", "vector", "rag", "retrieval", "hallucination", "jailbreak",
    "prompt leakage", "data poisoning", "training data", "fine-tuning",
    "langchain", "openai", "anthropic", "claude", "gemini"
}

# Keywords that indicate agentic AI involvement
AGENTIC_KEYWORDS = {
    "agent", "agentic", "autonomous", "tool calling", "function calling",
    "tool use", "mcp", "model context protocol", "web search", "browser",
    "multi-agent", "swarm", "orchestration", "goal", "task automation",
    "memory manipulation", "context window", "tool injection", "goal hijacking"
}

# Keywords that indicate web application risks (OWASP Top 10 Web)
WEB_APP_KEYWORDS = {
    "injection", "sql injection", "xss", "cross-site scripting", "command injection",
    "ldap injection", "authentication", "session", "access control", "authorization",
    "broken auth", "insecure design", "misconfiguration", "outdated component",
    "vulnerable dependency", "cryptographic", "encryption", "tls", "ssl",
    "logging", "monitoring", "ssrf", "server-side request forgery", "cors"
}

# Keywords that indicate API security risks
API_KEYWORDS = {
    "api", "rest", "graphql", "endpoint", "bola", "broken object",
    "api key", "rate limit", "throttling", "oauth", "jwt", "token"
}

# Keywords indicating red team / testing context
REDTEAM_KEYWORDS = {
    "red team", "penetration test", "security test", "adversarial",
    "attack simulation", "vulnerability assessment", "security audit"
}

# STRIDE category to reference mappings
STRIDE_REFERENCE_MAP = {
    "Spoofing": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "Tampering": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "Repudiation": ["OWASP_TOP10_2025"],
    "Information Disclosure": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "Denial of Service": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "Elevation of Privilege": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"]
}

# Specific threat categories to references
THREAT_CATEGORY_MAP = {
    # LLM-specific categories
    "prompt_injection": ["OWASP_LLM_TOP10", "OWASP_AGENTIC_THREATS"],
    "data_leakage": ["OWASP_LLM_TOP10", "OWASP_TOP10_2025"],
    "model_poisoning": ["OWASP_LLM_TOP10"],
    "excessive_agency": ["OWASP_LLM_TOP10", "OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],
    "output_handling": ["OWASP_LLM_TOP10", "OWASP_TOP10_2025"],
    
    # Agentic-specific categories
    "tool_abuse": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026", "OWASP_LLM_TOP10"],
    "autonomous_action": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],
    "memory_manipulation": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],
    "multi_agent_attack": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],
    "goal_hijacking": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],
    "mcp_exploitation": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],
    
    # Web/API categories
    "injection": ["OWASP_TOP10_2025"],
    "broken_access_control": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "authentication_failure": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "cryptographic_failure": ["OWASP_TOP10_2025"],
    "security_misconfiguration": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "ssrf": ["OWASP_TOP10_2025", "OWASP_API_TOP10_2023"],
    "supply_chain": ["OWASP_TOP10_2025", "OWASP_LLM_TOP10"]
}

# MAESTRO categories to references
MAESTRO_REFERENCE_MAP = {
    "AGENT01": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026", "OWASP_LLM_TOP10"],  # Autonomous Action Abuse
    "AGENT02": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],  # Multi-Agent Coordination
    "AGENT03": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026", "OWASP_LLM_TOP10"],  # Tool/MCP Exploitation
    "AGENT04": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026", "OWASP_LLM_TOP10"],  # Memory/Context Manipulation
    "AGENT05": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"],  # Goal/Objective Hijacking
    "AGENT06": ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026", "OWASP_LLM_TOP10"]   # LLM Decision Trust
}


class ReferenceMapper:
    """
    Deterministic reference mapper for security findings.
    
    Maps findings to OWASP references based on explicit evidence only.
    Never claims a mapping unless rules explicitly match.
    """
    
    def __init__(self):
        self.registry = get_reference_registry()
    
    def map_references(self, finding: Dict[str, Any]) -> MappingResult:
        """
        Map a finding to relevant OWASP references.
        
        DETERMINISTIC: Only maps based on explicit evidence in finding fields.
        If uncertain, returns empty references with unmapped_reason.
        
        Args:
            finding: Dictionary containing finding details (title, description, category, etc.)
        
        Returns:
            MappingResult with mapped reference IDs and reasons
        """
        finding_id = finding.get("id", "unknown")
        references: Set[str] = set()
        reasons: List[str] = []
        
        # Extract searchable text from finding
        text_fields = self._extract_text_fields(finding)
        text_lower = text_fields.lower()
        
        # 1. Check for explicit MAESTRO category
        maestro_cat = finding.get("maestro_category") or finding.get("agent_category")
        if maestro_cat and maestro_cat in MAESTRO_REFERENCE_MAP:
            refs = MAESTRO_REFERENCE_MAP[maestro_cat]
            references.update(refs)
            reasons.append(f"MAESTRO category '{maestro_cat}' mapped to: {', '.join(refs)}")
        
        # 2. Check for explicit threat category mapping
        category = finding.get("category", "").lower().replace(" ", "_").replace("-", "_")
        if category in THREAT_CATEGORY_MAP:
            refs = THREAT_CATEGORY_MAP[category]
            references.update(refs)
            reasons.append(f"Threat category '{category}' mapped to: {', '.join(refs)}")
        
        # 3. Check STRIDE category
        stride_cat = finding.get("stride_category")
        if stride_cat and stride_cat in STRIDE_REFERENCE_MAP:
            refs = STRIDE_REFERENCE_MAP[stride_cat]
            references.update(refs)
            reasons.append(f"STRIDE '{stride_cat}' mapped to: {', '.join(refs)}")
        
        # 4. Keyword-based detection (conservative)
        # Only add if strong keyword match found
        
        # Check for LLM/AI involvement
        if self._has_keyword_match(text_lower, LLM_AI_KEYWORDS, min_matches=2):
            references.add("OWASP_LLM_TOP10")
            reasons.append("LLM/AI keywords detected (multiple matches)")
        
        # Check for agentic involvement
        if self._has_keyword_match(text_lower, AGENTIC_KEYWORDS, min_matches=2):
            references.add("OWASP_AGENTIC_THREATS")
            references.add("OWASP_AGENTIC_TOP10_2026")
            reasons.append("Agentic AI keywords detected (multiple matches)")
        
        # Check for web app risks
        if self._has_keyword_match(text_lower, WEB_APP_KEYWORDS, min_matches=1):
            references.add("OWASP_TOP10_2025")
            reasons.append("Web application security keywords detected")
        
        # Check for API risks
        if self._has_keyword_match(text_lower, API_KEYWORDS, min_matches=2):
            references.add("OWASP_API_TOP10_2023")
            reasons.append("API security keywords detected (multiple matches)")
        
        # 5. Check for explicit OWASP mappings already in finding
        existing_owasp = finding.get("owasp_mapping") or finding.get("owasp_id")
        if existing_owasp:
            if "LLM" in str(existing_owasp):
                references.add("OWASP_LLM_TOP10")
                reasons.append(f"Pre-existing OWASP mapping: {existing_owasp}")
            elif "API" in str(existing_owasp):
                references.add("OWASP_API_TOP10_2023")
                reasons.append(f"Pre-existing OWASP mapping: {existing_owasp}")
            else:
                references.add("OWASP_TOP10_2025")
                reasons.append(f"Pre-existing OWASP mapping: {existing_owasp}")
        
        # 6. Check tags
        tags = finding.get("tags", [])
        if isinstance(tags, list):
            tag_str = " ".join(str(t).lower() for t in tags)
            if any(kw in tag_str for kw in ["agentic", "agent", "llm", "ai"]):
                references.add("OWASP_LLM_TOP10")
                reasons.append("AI-related tags present")
        
        # Determine confidence
        confidence = "low"
        if len(references) > 0:
            if len(reasons) >= 3:
                confidence = "high"
            elif len(reasons) >= 2:
                confidence = "medium"
            else:
                confidence = "low"
        
        # Handle unmapped findings
        unmapped_reason = None
        if not references:
            unmapped_reason = "No deterministic mapping rules matched. Finding flagged for manual review."
            logger.warning(
                "Unmapped finding",
                finding_id=finding_id,
                title=finding.get("title", "Unknown")
            )
        
        return MappingResult(
            finding_id=finding_id,
            reference_ids=list(references),
            mapping_reasons=reasons,
            confidence=confidence,
            unmapped_reason=unmapped_reason
        )
    
    def _extract_text_fields(self, finding: Dict) -> str:
        """Extract all text fields from finding for keyword search"""
        parts = []
        for key in ["title", "description", "category", "attack_vector", 
                    "affected_component", "detection_reason", "type"]:
            val = finding.get(key)
            if val:
                parts.append(str(val))
        
        # Include mitigations text
        mitigations = finding.get("mitigations", [])
        if isinstance(mitigations, list):
            parts.extend(str(m) for m in mitigations)
        
        return " ".join(parts)
    
    def _has_keyword_match(self, text: str, keywords: Set[str], min_matches: int = 1) -> bool:
        """Check if text contains at least min_matches keywords"""
        matches = sum(1 for kw in keywords if kw in text)
        return matches >= min_matches
    
    def map_all_findings(self, findings: List[Dict]) -> Dict[str, MappingResult]:
        """
        Map references for all findings.
        
        Returns:
            Dict mapping finding_id to MappingResult
        """
        return {
            f.get("id", f"finding_{i}"): self.map_references(f)
            for i, f in enumerate(findings)
        }
    
    def get_all_referenced_ids(self, findings: List[Dict]) -> List[str]:
        """Get all unique reference IDs used across findings"""
        all_refs: Set[str] = set()
        for finding in findings:
            result = self.map_references(finding)
            all_refs.update(result.reference_ids)
        return sorted(list(all_refs))
    
    def get_unmapped_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Get findings that couldn't be mapped to any reference.
        These should be flagged for manual review.
        """
        unmapped = []
        for finding in findings:
            result = self.map_references(finding)
            if not result.reference_ids:
                unmapped.append({
                    "finding_id": finding.get("id"),
                    "title": finding.get("title"),
                    "reason": result.unmapped_reason
                })
        return unmapped
    
    def enrich_findings_with_references(self, findings: List[Dict]) -> List[Dict]:
        """
        Add reference information to findings.
        
        Returns findings with added 'references' field containing:
        - reference_ids: List of reference IDs
        - references: List of resolved reference details
        - mapping_confidence: Confidence level of mapping
        """
        enriched = []
        for finding in findings:
            result = self.map_references(finding)
            
            # Create a copy with references added
            enriched_finding = dict(finding)
            enriched_finding["reference_ids"] = result.reference_ids
            enriched_finding["references"] = format_references_for_report(result.reference_ids)
            enriched_finding["mapping_confidence"] = result.confidence
            
            if result.unmapped_reason:
                enriched_finding["unmapped_reason"] = result.unmapped_reason
            
            enriched.append(enriched_finding)
        
        return enriched


# ===========================================
# Report-Type Specific Reference Formatting
# ===========================================

def get_references_for_report_type(
    findings: List[Dict],
    report_type: str,
    has_ai: bool = False,
    has_agents: bool = False
) -> Dict[str, Any]:
    """
    Get reference information formatted for specific report type.
    
    Report Types:
    - full: All references with detailed breakdown
    - executive: Top finding references + summary section
    - technical: All references + OWASP mapping notes
    - compliance: Control/governance references only
    
    Args:
        findings: List of threat findings
        report_type: Type of report being generated
        has_ai: Whether the system involves AI/LLM
        has_agents: Whether the system involves AI agents
    
    Returns:
        Dictionary with reference sections for the report
    """
    mapper = ReferenceMapper()
    registry = get_reference_registry()
    
    # Get all references used
    all_ref_ids = mapper.get_all_referenced_ids(findings)
    unmapped = mapper.get_unmapped_findings(findings)
    
    result = {
        "all_reference_ids": all_ref_ids,
        "unmapped_findings": unmapped if unmapped else None
    }
    
    if report_type == "full":
        # Full report: Complete reference listing
        result["external_references"] = registry.format_for_report(all_ref_ids)
        result["reference_summary"] = _generate_reference_summary(all_ref_ids, registry)
        result["findings_with_references"] = mapper.enrich_findings_with_references(findings)
        
    elif report_type == "executive":
        # Executive: Only top findings + brief standards section
        top_findings = sorted(findings, key=lambda x: x.get("overall_risk", 0), reverse=True)[:10]
        top_ref_ids = mapper.get_all_referenced_ids(top_findings)
        result["standards_referenced"] = registry.format_for_report(top_ref_ids)
        result["standards_summary"] = _generate_executive_standards_summary(top_ref_ids, has_ai, has_agents)
        
    elif report_type == "technical":
        # Technical: Full references + mapping notes
        result["external_references"] = registry.format_for_report(all_ref_ids)
        result["findings_with_references"] = mapper.enrich_findings_with_references(findings)
        result["owasp_mapping_notes"] = _generate_mapping_notes()
        
    elif report_type == "compliance":
        # Compliance: Governance references + control mapping
        result["control_governance_references"] = _get_compliance_references(has_ai, has_agents)
        result["finding_reference_mapping"] = [
            {
                "finding_id": f.get("id"),
                "title": f.get("title"),
                "reference_ids": mapper.map_references(f).reference_ids
            }
            for f in findings
        ]
        result["compliance_note"] = (
            "References mapped to guidance documents only. "
            "This does not constitute a compliance certification or audit."
        )
    
    return result


def _generate_reference_summary(ref_ids: List[str], registry) -> Dict:
    """Generate summary of references by category"""
    summary = {
        "total_references": len(ref_ids),
        "by_category": {}
    }
    
    for ref_id in ref_ids:
        ref = registry.get(ref_id)
        if ref:
            cat = ref.category.value
            if cat not in summary["by_category"]:
                summary["by_category"][cat] = []
            summary["by_category"][cat].append(ref.title)
    
    return summary


def _generate_executive_standards_summary(ref_ids: List[str], has_ai: bool, has_agents: bool) -> str:
    """Generate brief standards summary for executive report"""
    sections = []
    
    if "OWASP_TOP10_2025" in ref_ids:
        sections.append("OWASP Top 10:2025 for web application risks")
    
    if has_ai and "OWASP_LLM_TOP10" in ref_ids:
        sections.append("OWASP LLM Top 10 for AI/ML application risks")
    
    if has_agents and ("OWASP_AGENTIC_THREATS" in ref_ids or "OWASP_AGENTIC_TOP10_2026" in ref_ids):
        sections.append("OWASP Agentic AI guidance for autonomous agent risks")
    
    if not sections:
        return "Standard security guidance referenced where applicable."
    
    return "Security assessment references: " + "; ".join(sections) + "."


def _generate_mapping_notes() -> str:
    """Generate OWASP mapping methodology notes for technical report"""
    return """
OWASP Reference Mapping Methodology

References are assigned deterministically based on finding attributes:

1. MAESTRO Categories: Agentic AI threats (AGENT01-AGENT06) map to OWASP Agentic AI resources
2. STRIDE Categories: Traditional threat categories map to OWASP Top 10 Web/API
3. Keyword Detection: Finding text analyzed for security domain indicators
4. Pre-existing Mappings: Existing OWASP IDs in findings are preserved

Mapping Rules:
- LLM/AI findings → OWASP LLM Top 10
- Agentic/autonomous findings → OWASP Agentic AI Threats & Top 10
- Web application findings → OWASP Top 10:2025
- API-specific findings → OWASP API Security Top 10

NOTE: References indicate relevant guidance only. This is not a compliance assessment.
Unmapped findings are flagged for manual review and do not indicate lower risk.
"""


def _get_compliance_references(has_ai: bool, has_agents: bool) -> List[Dict]:
    """Get governance references for compliance report"""
    registry = get_reference_registry()
    refs = []
    
    # Always include web app reference
    web_ref = registry.get("OWASP_TOP10_2025")
    if web_ref:
        refs.append({
            **web_ref.to_dict(),
            "scope": "General web application security risks",
            "applicability": "All web applications"
        })
    
    # Include LLM reference if AI is in scope
    if has_ai:
        llm_ref = registry.get("OWASP_LLM_TOP10")
        if llm_ref:
            refs.append({
                **llm_ref.to_dict(),
                "scope": "LLM and GenAI application risks",
                "applicability": "Systems using LLMs, ChatGPT, or similar AI"
            })
    
    # Include agentic references if agents are in scope
    if has_agents:
        for ref_id in ["OWASP_AGENTIC_THREATS", "OWASP_AGENTIC_TOP10_2026"]:
            ref = registry.get(ref_id)
            if ref:
                refs.append({
                    **ref.to_dict(),
                    "scope": "Autonomous AI agent risks",
                    "applicability": "Systems with AI agents, tool calling, or autonomous actions"
                })
    
    return refs


# Global mapper instance
_mapper = None


def get_reference_mapper() -> ReferenceMapper:
    """Get global reference mapper singleton"""
    global _mapper
    if _mapper is None:
        _mapper = ReferenceMapper()
    return _mapper


# Convenience function
def map_finding_references(finding: Dict) -> MappingResult:
    """Map a single finding to references"""
    return get_reference_mapper().map_references(finding)
