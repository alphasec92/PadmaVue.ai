"""
Tests for MAESTRO (Agentic AI) threat analysis functionality.

Tests:
1. Applicability detection - returns not_applicable when no AI signals
2. Applicability detection - returns applicable when AI signals present
3. Force flag overrides detection
4. Threat generation only when applicable
"""

import pytest
from app.engines.maestro import MAESTROEngine, MaestroApplicability


class TestMaestroApplicability:
    """Test MAESTRO applicability detection."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = MAESTROEngine()
    
    def test_not_applicable_no_ai_signals(self):
        """MAESTRO should return not_applicable when no AI/agent signals exist."""
        project_data = {
            "id": "test-project-1",
            "name": "Simple Web App",
            "description": "A basic CRUD application with user authentication",
            "files": [],
            "metadata": {}
        }
        
        elicitation_results = {
            "answers": {
                "components": ["web server", "database", "user interface"],
                "data_flows": ["user -> server -> database"]
            },
            "summary": "Simple web application with login functionality"
        }
        
        result = self.engine.check_applicability(
            project_data=project_data,
            elicitation_results=elicitation_results
        )
        
        assert result.applicable is False
        assert result.status == "not_detected"
        assert result.confidence >= 0.9  # High confidence it's NOT applicable
        assert len(result.evidence) == 0
        assert "No AI/agent components detected" in result.reasons[0]
    
    def test_applicable_with_llm_keywords(self):
        """MAESTRO should detect LLM-related keywords and return applicable."""
        project_data = {
            "id": "test-project-2",
            "name": "AI Chatbot Assistant",
            "description": "A chatbot using OpenAI GPT for customer support",
            "files": [{"name": "llm_service.py"}],
            "metadata": {"llm_provider": "openai"}
        }
        
        elicitation_results = {
            "answers": {
                "components": ["LLM service", "chat interface", "embedding store"],
                "ai_features": "yes"
            },
            "summary": "AI-powered chatbot using OpenAI GPT-4 for responses"
        }
        
        result = self.engine.check_applicability(
            project_data=project_data,
            elicitation_results=elicitation_results
        )
        
        assert result.applicable is True
        assert result.status == "detected"
        assert result.confidence >= 0.5
        assert len(result.evidence) > 0
        assert any("llm" in r.lower() or "openai" in r.lower() or "gpt" in r.lower() 
                   for r in result.reasons)
    
    def test_applicable_with_agent_keywords(self):
        """MAESTRO should detect agent-related keywords and return applicable."""
        project_data = {
            "id": "test-project-3",
            "name": "Multi-Agent System",
            "description": "A LangGraph-based multi-agent orchestration system",
            "files": [
                {"name": "agents/orchestrator.py"},
                {"name": "agents/tool_executor.py"}
            ],
            "metadata": {}
        }
        
        elicitation_results = {
            "answers": {
                "components": ["agent coordinator", "tool executor", "memory store"],
                "frameworks": "LangGraph, LangChain"
            },
            "summary": "Multi-agent system with autonomous tool execution"
        }
        
        result = self.engine.check_applicability(
            project_data=project_data,
            elicitation_results=elicitation_results
        )
        
        assert result.applicable is True
        assert result.status == "detected"
        assert len(result.evidence) > 0
        assert any("agent" in e.get("snippet", "").lower() 
                   for e in result.evidence)
    
    def test_applicable_with_mcp_config(self):
        """MAESTRO should detect MCP configuration and return applicable."""
        project_data = {
            "id": "test-project-4",
            "name": "MCP-Enabled App",
            "description": "Application with Model Context Protocol servers",
            "files": [],
            "metadata": {"mcp_servers": ["file-server", "db-server"]}
        }
        
        result = self.engine.check_applicability(
            project_data=project_data,
            metadata={"mcp_servers": ["server1"]}
        )
        
        assert result.applicable is True
        assert "MCP" in str(result.signals.get("explicit", []))
    
    def test_force_flag_returns_applicable(self):
        """When force=True, should return applicable regardless of detection."""
        project_data = {
            "id": "test-project-5",
            "name": "Static Website",
            "description": "A simple HTML/CSS website with no AI",
            "files": [],
            "metadata": {}
        }
        
        # Without force - should be not applicable
        result_normal = self.engine.check_applicability(
            project_data=project_data,
            force=False
        )
        assert result_normal.applicable is False
        assert result_normal.status == "not_detected"
        
        # With force - should be applicable but marked as forced
        result_forced = self.engine.check_applicability(
            project_data=project_data,
            force=True
        )
        assert result_forced.applicable is True
        assert result_forced.status == "forced"
        assert result_forced.confidence == 0.5  # Lower confidence for forced
    
    def test_parsed_content_detection(self):
        """MAESTRO should detect AI signals in parsed document content."""
        project_data = {
            "id": "test-project-6",
            "name": "Architecture Doc",
            "description": "Architecture documentation",
            "files": [],
            "metadata": {}
        }
        
        parsed_content = """
        System Architecture:
        
        1. Frontend: React application
        2. Backend: FastAPI with LangChain integration
        3. AI Layer: 
           - Uses ChatOpenAI for conversation
           - VectorStore (Chroma) for RAG
           - Agent with tool execution capabilities
        4. Database: PostgreSQL
        """
        
        result = self.engine.check_applicability(
            project_data=project_data,
            parsed_content=parsed_content
        )
        
        assert result.applicable is True
        assert len(result.evidence) > 0


class TestMaestroThreatGeneration:
    """Test MAESTRO threat generation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = MAESTROEngine()
    
    def test_generates_threats_when_applicable(self):
        """Should generate MAESTRO threats when applicability is positive."""
        project_data = {
            "id": "test-gen-1",
            "name": "AI Agent App",
            "description": "Multi-agent system with tool use",
            "files": [],
            "metadata": {}
        }
        
        elicitation_results = {
            "answers": {
                "components": ["orchestrator agent", "tool executor", "MCP server"],
                "ai_features": "autonomous tool execution, memory, web search"
            },
            "summary": "LangGraph multi-agent with MCP tools"
        }
        
        # First check applicability
        applicability = self.engine.check_applicability(
            project_data=project_data,
            elicitation_results=elicitation_results
        )
        
        # Then generate threats
        threats = self.engine.generate_threats(
            project_data=project_data,
            elicitation_results=elicitation_results,
            applicability=applicability
        )
        
        assert len(threats) > 0
        assert all(t.get("methodology") == "maestro" for t in threats)
        assert all(t.get("category", "").startswith("AGENT") for t in threats)
    
    def test_no_threats_when_not_applicable(self):
        """Should NOT generate threats when applicability is negative."""
        project_data = {
            "id": "test-gen-2",
            "name": "Simple API",
            "description": "REST API with no AI",
            "files": [],
            "metadata": {}
        }
        
        applicability = MaestroApplicability(
            applicable=False,
            confidence=0.9,
            reasons=["No AI components detected"],
            evidence=[],
            signals={},
            status="not_detected"
        )
        
        threats = self.engine.generate_threats(
            project_data=project_data,
            applicability=applicability
        )
        
        # Should return empty list when not applicable
        assert len(threats) == 0
    
    def test_threat_categories_match_signals(self):
        """Generated threats should match detected signals."""
        project_data = {
            "id": "test-gen-3",
            "name": "RAG App",
            "description": "RAG application with vector store",
            "files": [],
            "metadata": {}
        }
        
        elicitation_results = {
            "answers": {
                "components": ["vector database", "embedding service", "RAG retrieval"],
            },
            "summary": "Retrieval augmented generation with embeddings"
        }
        
        applicability = self.engine.check_applicability(
            project_data=project_data,
            elicitation_results=elicitation_results
        )
        
        threats = self.engine.generate_threats(
            project_data=project_data,
            elicitation_results=elicitation_results,
            applicability=applicability
        )
        
        # Should include memory/context related threats (AGENT04)
        categories = [t.get("category") for t in threats]
        assert "AGENT04" in categories or "AGENT05" in categories  # Memory or goal hijacking


class TestMaestroCategories:
    """Test MAESTRO category definitions."""
    
    def test_all_categories_defined(self):
        """All MAESTRO categories should be defined."""
        engine = MAESTROEngine()
        categories = engine.get_all_categories()
        
        expected = ["AGENT01", "AGENT02", "AGENT03", "AGENT04", "AGENT05", "AGENT06"]
        assert all(cat in categories for cat in expected)
    
    def test_categories_have_required_fields(self):
        """Each category should have required fields."""
        engine = MAESTROEngine()
        categories = engine.get_all_categories()
        
        for cat_id, cat in categories.items():
            assert "id" in cat
            assert "name" in cat
            assert "description" in cat
            assert "examples" in cat
            assert "mitigations" in cat
            assert len(cat["examples"]) > 0
            assert len(cat["mitigations"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
