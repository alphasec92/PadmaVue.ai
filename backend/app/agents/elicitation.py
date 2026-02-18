"""
Elicitation Agent
Identifies missing information and generates clarifying questions
"""

from typing import Dict, Any, List, Optional
import json

import structlog

from app.services.llm_provider import LLMProvider

logger = structlog.get_logger()


class ElicitationAgent:
    """
    Elicitation Agent for identifying information gaps.
    
    Responsibilities:
    - Analyze provided documentation
    - Identify missing security-relevant information
    - Generate clarifying questions
    - Make reasonable assumptions
    """
    
    SYSTEM_PROMPT = """You are a Security Elicitation Agent specialized in identifying 
missing information for threat modeling. Your role is to:

1. Analyze the provided system documentation
2. Identify gaps in security-relevant information
3. Generate targeted questions to fill those gaps
4. Make reasonable assumptions where information is missing

Focus on:
- Authentication and authorization mechanisms
- Data classification and sensitivity
- Network architecture and trust boundaries
- Third-party integrations
- Deployment environment
- Compliance requirements

Output format: JSON with 'questions' and 'assumptions' arrays."""
    
    def __init__(self, llm: LLMProvider):
        self.llm = llm
    
    async def run(
        self,
        project_data: Dict[str, Any],
        parsed_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run elicitation analysis on project data.
        
        Args:
            project_data: Project metadata and content
            parsed_content: Optional parsed document content for richer context
        
        Returns:
            Questions and assumptions dict
        """
        logger.info("Running elicitation analysis",
                    has_parsed_content=parsed_content is not None)
        
        # Build context from project data
        context = self._build_context(project_data, parsed_content)
        
        # Generate prompt
        prompt = f"""Analyze the following system documentation and identify missing information 
that would be needed for a comprehensive security threat model.

## System Documentation
{context}

## Analysis Required
1. List 5-10 specific questions that would help complete the threat model
2. List 3-5 reasonable assumptions based on the available information
3. Identify any critical security areas with insufficient information

Respond with valid JSON:
{{
    "questions": ["question1", "question2", ...],
    "assumptions": ["assumption1", "assumption2", ...],
    "critical_gaps": ["gap1", "gap2", ...]
}}"""
        
        try:
            response = await self.llm.generate(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temp=0.3
            )
            
            # Parse response
            result = self._parse_response(response)
            
            logger.info("Elicitation complete",
                       questions=len(result.get("questions", [])),
                       assumptions=len(result.get("assumptions", [])))
            
            return result
            
        except Exception as e:
            logger.error("Elicitation failed", error=str(e))
            return self._get_default_results()
    
    def _build_context(self, project_data: Dict[str, Any], parsed_content: Optional[str] = None) -> str:
        """Build context string from project data and parsed file content"""
        parts = []
        
        # Add project metadata
        parts.append(f"Project Name: {project_data.get('project_name', 'Unknown')}")
        parts.append(f"Description: {project_data.get('description', 'No description')}")
        
        # Add file information
        files = project_data.get("files", [])
        if files:
            parts.append(f"\nDocuments analyzed: {len(files)}")
            for f in files[:5]:  # Limit to first 5
                name = f.get('original_name', f.get('filename', 'unknown'))
                parts.append(f"  - {name}")
        
        # Add actual document content if available
        if parsed_content:
            # Limit content to avoid token overflow (keep first 8000 chars)
            content_preview = parsed_content[:8000]
            if len(parsed_content) > 8000:
                content_preview += "\n... [content truncated for analysis]"
            parts.append(f"\n## Document Content\n{content_preview}")
        else:
            # Fallback: try to get parsed_content from individual files
            for f in files[:3]:
                fc = f.get('parsed_content', '')
                if fc:
                    content_preview = fc[:4000]
                    if len(fc) > 4000:
                        content_preview += "\n... [truncated]"
                    name = f.get('original_name', f.get('filename', 'unknown'))
                    parts.append(f"\n## Content from {name}\n{content_preview}")
        
        # Add chunk count
        parts.append(f"\nTotal content chunks: {project_data.get('total_chunks', 0)}")
        
        return "\n".join(parts)
    
    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response to structured data"""
        try:
            # Try to extract JSON from response
            start = response.find("{")
            end = response.rfind("}") + 1
            
            if start >= 0 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback to default results
        return self._get_default_results()
    
    def _get_default_results(self) -> Dict[str, Any]:
        """Return default elicitation results"""
        return {
            "questions": [
                "What authentication mechanisms are currently in place (OAuth, JWT, session-based)?",
                "How is sensitive data encrypted at rest and in transit?",
                "What is the deployment environment (cloud provider, on-premise, hybrid)?",
                "Are there any third-party integrations that handle sensitive data?",
                "What is the expected user base and typical traffic patterns?",
                "Are there specific regulatory compliance requirements (GDPR, HIPAA, PCI-DSS)?",
                "How are secrets and API keys currently managed?",
                "What logging and monitoring capabilities exist?",
                "Is there a WAF or API gateway in front of the application?",
                "What is the data retention policy for user information?"
            ],
            "assumptions": [
                "Standard web application architecture with frontend/backend separation",
                "Database contains sensitive user information requiring protection",
                "API endpoints are accessible over HTTPS",
                "Authentication is required for most application functionality",
                "Application handles personally identifiable information (PII)"
            ],
            "critical_gaps": [
                "Authentication mechanism details",
                "Data classification scheme",
                "Network architecture and trust boundaries",
                "Incident response procedures"
            ]
        }
    
    async def refine_questions(
        self,
        initial_questions: List[str],
        user_responses: Dict[str, str]
    ) -> List[str]:
        """
        Generate follow-up questions based on user responses.
        
        Args:
            initial_questions: Original questions asked
            user_responses: User's answers to questions
        
        Returns:
            List of follow-up questions
        """
        prompt = f"""Based on the following Q&A exchange, generate follow-up questions 
to clarify any remaining ambiguities for security threat modeling.

## Previous Questions and Answers
{json.dumps(user_responses, indent=2)}

Generate 3-5 targeted follow-up questions. Return as JSON array of strings."""
        
        try:
            response = await self.llm.generate(prompt, temp=0.4)
            
            # Parse response
            start = response.find("[")
            end = response.rfind("]") + 1
            
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except:
            pass
        
        return []


