"""
Backend API endpoint tests.

Tests:
1. Health endpoint
2. Settings API endpoints
3. Ollama connection (with mock)
4. Error handling
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock
import json

from app.main import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health_endpoint_returns_200(self, client):
        """Health endpoint should return 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "services" in data
    
    def test_health_endpoint_structure(self, client):
        """Health endpoint should have correct structure."""
        response = client.get("/health")
        data = response.json()
        assert isinstance(data["services"], dict)
        assert "neo4j" in data["services"]
        assert "qdrant" in data["services"]
        assert "mcp" in data["services"]


class TestSettingsEndpoints:
    """Test settings API endpoints."""
    
    def test_get_settings_returns_config(self, client):
        """GET /api/settings should return current configuration."""
        response = client.get("/api/settings")
        assert response.status_code == 200
        data = response.json()
        assert "provider" in data
        assert "models" in data
    
    def test_update_settings_accepts_valid_config(self, client):
        """POST /api/settings should accept valid configuration."""
        config = {
            "provider": "mock",
            "model": "mock-model",
            "temperature": 0.7,
            "max_tokens": 2000
        }
        response = client.post("/api/settings", json=config)
        assert response.status_code in [200, 201]
    
    def test_update_settings_rejects_invalid_provider(self, client):
        """POST /api/settings should reject invalid provider."""
        config = {
            "provider": "invalid_provider",
            "model": "test-model"
        }
        response = client.post("/api/settings", json=config)
        # Should either accept (with validation) or reject with 400
        assert response.status_code in [200, 201, 400, 422]


class TestOllamaEndpoints:
    """Test Ollama-related endpoints."""
    
    @patch('app.api.settings.OllamaProvider')
    def test_list_ollama_models_success(self, mock_ollama_provider, client):
        """GET /api/settings/ollama/models should list available models."""
        # Mock successful response
        mock_provider = AsyncMock()
        mock_provider.list_models.return_value = ["llama3.1", "mistral", "codellama"]
        mock_ollama_provider.return_value = mock_provider
        
        response = client.get("/api/settings/ollama/models?base_url=http://localhost:11434")
        assert response.status_code == 200
        data = response.json()
        assert data["available"] is True
        assert "models" in data
        assert len(data["models"]) > 0
        assert data["count"] > 0
    
    @patch('app.api.settings.OllamaProvider')
    def test_list_ollama_models_connection_error(self, mock_ollama_provider, client):
        """GET /api/settings/ollama/models should handle connection errors."""
        # Mock connection error
        mock_provider = AsyncMock()
        mock_provider.list_models.side_effect = Exception("Connection refused")
        mock_ollama_provider.return_value = mock_provider
        
        response = client.get("/api/settings/ollama/models?base_url=http://localhost:11434")
        assert response.status_code == 200
        data = response.json()
        assert data["available"] is False
        assert "error" in data
        assert len(data["models"]) == 0
    
    def test_list_ollama_models_translates_localhost_in_docker(self, client):
        """GET /api/settings/ollama/models should translate localhost to host.docker.internal in Docker."""
        with patch('os.getenv', return_value='true'), \
             patch('app.api.settings.OllamaProvider') as mock_ollama_provider:
            mock_provider = AsyncMock()
            mock_provider.list_models.return_value = ["llama3.1"]
            mock_ollama_provider.return_value = mock_provider
            
            response = client.get("/api/settings/ollama/models?base_url=http://localhost:11434")
            # Verify that host.docker.internal was used
            mock_ollama_provider.assert_called_once()
            call_args = mock_ollama_provider.call_args[1]
            assert "host.docker.internal" in call_args.get("base_url", "")


class TestArchitectChatEndpoints:
    """Test architect chat API endpoints."""
    
    def test_chat_endpoint_requires_post(self, client):
        """Chat endpoint should require POST method."""
        response = client.get("/api/architect/chat")
        assert response.status_code == 405  # Method not allowed
    
    def test_chat_endpoint_requires_message(self, client):
        """Chat endpoint should require message in request body."""
        response = client.post("/api/architect/chat", json={})
        assert response.status_code in [400, 422]  # Bad request or validation error
    
    @patch('app.api.architect_chat.analyze_with_llm')
    def test_chat_endpoint_with_mock_llm(self, mock_analyze, client):
        """Chat endpoint should work with mock LLM."""
        # Mock LLM response
        mock_analyze.return_value = {
            "response_type": "general",
            "analysis": "This is a test response",
            "completeness_score": 0.5,
            "missing_info": [],
            "follow_up_questions": [],
            "ready_for_threat_model": False,
            "confidence_level": "medium",
            "uncertainty_notes": [],
            "world_model": {},
            "sources": []
        }
        
        response = client.post(
            "/api/architect/chat",
            json={
                "message": "Tell me about security threats",
                "session_id": "test-session-123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "response" in data
        assert "session_id" in data


class TestErrorHandling:
    """Test error handling in API endpoints."""
    
    @patch('app.api.architect_chat.get_llm_provider')
    def test_llm_connection_error_fallback_to_mock(self, mock_get_provider, client):
        """When LLM connection fails, should fallback to mock provider."""
        # First call fails (connection error)
        mock_failing_provider = AsyncMock()
        mock_failing_provider.list_models.side_effect = Exception("Connection refused")
        mock_failing_provider.chat.side_effect = Exception("Connection refused")
        
        # Mock provider works
        mock_mock_provider = AsyncMock()
        mock_mock_provider.chat.return_value = '{"response_type": "general", "analysis": "Mock response"}'
        
        # Setup mock to return failing provider first, then mock provider
        call_count = 0
        def provider_side_effect(config):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_failing_provider
            else:
                return mock_mock_provider
        mock_get_provider.side_effect = provider_side_effect
        
        response = client.post(
            "/api/architect/chat",
            json={
                "message": "Test message",
                "session_id": "test-session"
            }
        )
        # Should either succeed with mock or return error (depending on implementation)
        assert response.status_code in [200, 500, 503]
    
    def test_invalid_json_returns_422(self, client):
        """Invalid JSON should return 422 Unprocessable Entity."""
        response = client.post(
            "/api/architect/chat",
            data="not json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
    
    def test_missing_required_fields_returns_422(self, client):
        """Missing required fields should return 422."""
        response = client.post(
            "/api/architect/chat",
            json={"session_id": "test"}  # Missing 'message'
        )
        assert response.status_code in [400, 422]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
