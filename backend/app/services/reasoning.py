"""
Reasoning Service for Thinking Time Control
Provides Fast/Balanced/Deep reasoning modes with safe summaries
"""

import structlog
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

from app.config import settings

logger = structlog.get_logger()


class ReasoningLevel(str, Enum):
    """Reasoning depth levels"""
    FAST = "fast"       # Quick response, minimal reasoning
    BALANCED = "balanced"  # Default, moderate reasoning
    DEEP = "deep"       # Extensive reasoning, multiple passes


@dataclass
class ReasoningSummary:
    """
    Safe reasoning summary - does NOT expose raw chain-of-thought.
    Only shows key steps, assumptions, and evidence used.
    """
    key_steps: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    evidence_used: List[str] = field(default_factory=list)
    confidence: str = "medium"  # low, medium, high
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_steps": self.key_steps,
            "assumptions": self.assumptions,
            "evidence_used": self.evidence_used,
            "confidence": self.confidence
        }
    
    def to_markdown(self) -> str:
        """Format as concise markdown bullet points"""
        lines = []
        
        if self.key_steps:
            lines.append("**Key Steps:**")
            for step in self.key_steps[:5]:  # Limit to 5
                lines.append(f"• {step}")
        
        if self.assumptions:
            lines.append("\n**Assumptions:**")
            for assumption in self.assumptions[:3]:  # Limit to 3
                lines.append(f"• {assumption}")
        
        if self.evidence_used:
            lines.append("\n**Evidence Used:**")
            for evidence in self.evidence_used[:5]:  # Limit to 5
                lines.append(f"• {evidence}")
        
        if self.confidence:
            lines.append(f"\n**Confidence:** {self.confidence}")
        
        return "\n".join(lines)


@dataclass
class ReasoningPolicy:
    """
    LLM reasoning policy based on provider and level.
    Maps reasoning levels to provider-specific settings.
    """
    level: ReasoningLevel
    provider: str
    
    # Provider-specific settings
    temperature: float = 0.3
    max_tokens: int = 2000
    use_extended_thinking: bool = False
    thinking_budget: int = 0
    reasoning_effort: str = "medium"  # for OpenAI o-series
    num_passes: int = 1  # for multi-pass reasoning
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "provider": self.provider,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "use_extended_thinking": self.use_extended_thinking,
            "thinking_budget": self.thinking_budget,
            "reasoning_effort": self.reasoning_effort,
            "num_passes": self.num_passes,
        }


class ReasoningService:
    """
    Service for managing reasoning levels and generating safe summaries.
    """
    
    # Provider-specific reasoning configurations
    PROVIDER_CONFIGS = {
        "openai": {
            ReasoningLevel.FAST: {
                "temperature": 0.5,
                "max_tokens": 1500,
                "reasoning_effort": "low",
                "num_passes": 1,
            },
            ReasoningLevel.BALANCED: {
                "temperature": 0.3,
                "max_tokens": 2500,
                "reasoning_effort": "medium",
                "num_passes": 1,
            },
            ReasoningLevel.DEEP: {
                "temperature": 0.2,
                "max_tokens": 4000,
                "reasoning_effort": "high",
                "num_passes": 2,  # Draft + refine
            },
        },
        "anthropic": {
            ReasoningLevel.FAST: {
                "temperature": 0.5,
                "max_tokens": 1500,
                "use_extended_thinking": False,
                "thinking_budget": 0,
                "num_passes": 1,
            },
            ReasoningLevel.BALANCED: {
                "temperature": 0.3,
                "max_tokens": 2500,
                "use_extended_thinking": False,
                "thinking_budget": 0,
                "num_passes": 1,
            },
            ReasoningLevel.DEEP: {
                "temperature": 0.2,
                "max_tokens": 4000,
                "use_extended_thinking": True,
                "thinking_budget": 10000,
                "num_passes": 1,  # Extended thinking handles depth
            },
        },
        "default": {
            ReasoningLevel.FAST: {
                "temperature": 0.5,
                "max_tokens": 1500,
                "num_passes": 1,
            },
            ReasoningLevel.BALANCED: {
                "temperature": 0.3,
                "max_tokens": 2500,
                "num_passes": 1,
            },
            ReasoningLevel.DEEP: {
                "temperature": 0.2,
                "max_tokens": 4000,
                "num_passes": 3,  # Draft -> Critique -> Final
            },
        },
    }
    
    def __init__(self):
        self._default_level = ReasoningLevel(
            getattr(settings, 'REASONING_LEVEL', 'balanced').lower()
        )
        self._show_summary = getattr(settings, 'SHOW_REASONING_SUMMARY', True)
    
    @property
    def default_level(self) -> ReasoningLevel:
        return self._default_level
    
    @property
    def show_summary(self) -> bool:
        return self._show_summary
    
    def get_policy(
        self, 
        provider: str, 
        level: Optional[ReasoningLevel] = None
    ) -> ReasoningPolicy:
        """
        Get reasoning policy for a provider and level.
        
        Args:
            provider: LLM provider name (openai, anthropic, etc.)
            level: Reasoning level (defaults to configured level)
        
        Returns:
            ReasoningPolicy with provider-specific settings
        """
        level = level or self._default_level
        provider = provider.lower()
        
        # Get provider config or fall back to default
        provider_config = self.PROVIDER_CONFIGS.get(
            provider, 
            self.PROVIDER_CONFIGS["default"]
        )
        level_config = provider_config.get(level, provider_config[ReasoningLevel.BALANCED])
        
        return ReasoningPolicy(
            level=level,
            provider=provider,
            temperature=level_config.get("temperature", 0.3),
            max_tokens=level_config.get("max_tokens", 2000),
            use_extended_thinking=level_config.get("use_extended_thinking", False),
            thinking_budget=level_config.get("thinking_budget", 0),
            reasoning_effort=level_config.get("reasoning_effort", "medium"),
            num_passes=level_config.get("num_passes", 1),
        )
    
    def create_summary(
        self,
        key_steps: List[str] = None,
        assumptions: List[str] = None,
        evidence_used: List[str] = None,
        confidence: str = "medium"
    ) -> Optional[ReasoningSummary]:
        """
        Create a safe reasoning summary (if enabled).
        
        IMPORTANT: This does NOT expose raw chain-of-thought.
        Only curated bullet points are shown.
        """
        if not self._show_summary:
            return None
        
        return ReasoningSummary(
            key_steps=key_steps or [],
            assumptions=assumptions or [],
            evidence_used=evidence_used or [],
            confidence=confidence
        )
    
    def extract_summary_from_response(
        self,
        response_text: str,
        sources: List[str] = None,
        world_model: Dict[str, Any] = None,
        completeness_score: float = 0.0
    ) -> ReasoningSummary:
        """
        Extract a comprehensive reasoning summary from LLM response.
        
        This generates meaningful insights about the analysis process.
        """
        key_steps = []
        assumptions = []
        evidence_used = []
        
        # Generate key analysis steps based on content
        text_lower = response_text.lower()
        
        # Security analysis steps
        if any(term in text_lower for term in ['threat', 'risk', 'vulnerability', 'attack']):
            key_steps.append("Analyzing potential security threats and attack vectors")
        
        if any(term in text_lower for term in ['authentication', 'auth', 'login', 'credential']):
            key_steps.append("Evaluating authentication mechanisms and identity management")
        
        if any(term in text_lower for term in ['data', 'encrypt', 'sensitive', 'pii', 'privacy']):
            key_steps.append("Assessing data protection and privacy controls")
        
        if any(term in text_lower for term in ['api', 'endpoint', 'interface', 'service']):
            key_steps.append("Reviewing API security and service boundaries")
        
        if any(term in text_lower for term in ['database', 'storage', 'persist']):
            key_steps.append("Examining data storage security patterns")
        
        if any(term in text_lower for term in ['network', 'firewall', 'traffic', 'communication']):
            key_steps.append("Analyzing network security and communication channels")
        
        if any(term in text_lower for term in ['cloud', 'aws', 'azure', 'gcp', 'kubernetes']):
            key_steps.append("Considering cloud infrastructure security posture")
        
        if any(term in text_lower for term in ['compliance', 'regulation', 'gdpr', 'hipaa', 'pci']):
            key_steps.append("Mapping to compliance and regulatory requirements")
        
        # Extract bullet points from response
        lines = response_text.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith(('•', '-', '*', '1.', '2.', '3.', '4.', '5.')):
                clean_line = line.lstrip('•-*0123456789. ')
                if len(clean_line) > 15 and len(clean_line) < 200:
                    if len(key_steps) < 8:
                        key_steps.append(clean_line)
        
        # Generate assumptions based on world model
        if world_model:
            if world_model.get('system_type'):
                assumptions.append(f"System type: {world_model['system_type']}")
            
            if world_model.get('components'):
                comp_count = len(world_model['components'])
                assumptions.append(f"Architecture includes {comp_count} identified components")
            
            if world_model.get('data_types'):
                data_types = ', '.join(world_model['data_types'][:3])
                assumptions.append(f"Handles data types: {data_types}")
            
            if world_model.get('auth_method'):
                assumptions.append(f"Authentication: {world_model['auth_method']}")
            
            if world_model.get('network_exposure'):
                assumptions.append(f"Network exposure: {world_model['network_exposure']}")
        
        # Add default assumptions if none found
        if not assumptions:
            if 'web' in text_lower:
                assumptions.append("Assuming web-based application architecture")
            if 'user' in text_lower:
                assumptions.append("Multiple user roles and access levels expected")
            if 'external' in text_lower or 'third-party' in text_lower:
                assumptions.append("Third-party integrations may introduce additional risks")
        
        # Evidence used
        if sources:
            evidence_used = [f"Source: {s}" for s in sources[:5]]
        
        # Add analysis context as evidence
        if 'stride' in text_lower:
            evidence_used.append("STRIDE threat modeling methodology applied")
        if 'owasp' in text_lower:
            evidence_used.append("OWASP security guidelines referenced")
        if 'nist' in text_lower:
            evidence_used.append("NIST security framework considered")
        
        # Determine confidence based on multiple factors
        confidence = "medium"
        
        # High confidence indicators
        high_confidence_indicators = sum([
            completeness_score > 0.7,
            len(key_steps) >= 5,
            len(assumptions) >= 3,
            bool(world_model and world_model.get('components')),
            "certain" in text_lower or "confident" in text_lower,
        ])
        
        # Low confidence indicators
        low_confidence_indicators = sum([
            completeness_score < 0.3,
            "uncertain" in text_lower or "not sure" in text_lower,
            "need more information" in text_lower,
            "unclear" in text_lower,
            len(key_steps) < 2,
        ])
        
        if high_confidence_indicators >= 3:
            confidence = "high"
        elif low_confidence_indicators >= 2:
            confidence = "low"
        
        # Ensure we have some content
        if not key_steps:
            key_steps = [
                "Gathering system architecture information",
                "Identifying security-relevant components",
                "Building context for threat analysis"
            ]
        
        return ReasoningSummary(
            key_steps=key_steps[:8],  # Allow more steps
            assumptions=assumptions[:5],  # Allow more assumptions
            evidence_used=evidence_used[:5],
            confidence=confidence
        )
    
    def get_multi_pass_prompts(self, level: ReasoningLevel, base_prompt: str) -> List[str]:
        """
        Get prompts for multi-pass reasoning (for deep mode on basic models).
        
        Pass 1: Initial draft
        Pass 2: Self-critique  
        Pass 3: Final refined answer
        """
        if level != ReasoningLevel.DEEP:
            return [base_prompt]
        
        return [
            # Pass 1: Draft
            f"{base_prompt}\n\nProvide your initial analysis.",
            
            # Pass 2: Critique
            "Review your previous response critically. What might be wrong, missing, or could be improved? List specific issues.",
            
            # Pass 3: Final
            "Based on your self-critique, provide a final, refined answer that addresses the issues you identified.",
        ]


# Global service instance
reasoning_service = ReasoningService()


def get_reasoning_service() -> ReasoningService:
    """Get the global reasoning service instance"""
    return reasoning_service
