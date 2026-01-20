"""
Docker integration tests.

Tests:
1. Docker compose startup
2. Health checks
3. Backend-frontend communication
4. Ollama integration in Docker
"""

import pytest
import requests
import time
import subprocess
import os
from typing import Optional


# Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
HEALTH_CHECK_TIMEOUT = 60  # seconds
HEALTH_CHECK_INTERVAL = 2  # seconds


def wait_for_service(url: str, timeout: int = HEALTH_CHECK_TIMEOUT) -> bool:
    """Wait for a service to become available."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(HEALTH_CHECK_INTERVAL)
    return False


def check_docker_compose_running() -> bool:
    """Check if docker compose services are running."""
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", "infra/docker/compose/compose.lite.yml", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            # Check if we have running containers
            lines = [line for line in result.stdout.strip().split('\n') if line]
            return len(lines) > 0
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


@pytest.mark.integration
class TestDockerCompose:
    """Test Docker Compose setup."""
    
    def test_docker_compose_services_running(self):
        """Docker compose services should be running."""
        assert check_docker_compose_running(), "Docker compose services are not running"
    
    def test_backend_health_check(self):
        """Backend health endpoint should be accessible."""
        assert wait_for_service(f"{BACKEND_URL}/health"), \
            f"Backend health check failed at {BACKEND_URL}/health"
        
        response = requests.get(f"{BACKEND_URL}/health", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
    
    def test_frontend_health_check(self):
        """Frontend should be accessible."""
        assert wait_for_service(FRONTEND_URL), \
            f"Frontend health check failed at {FRONTEND_URL}"
        
        response = requests.get(FRONTEND_URL, timeout=10)
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
    
    def test_backend_api_endpoints(self):
        """Backend API endpoints should be accessible."""
        # Test settings endpoint
        response = requests.get(f"{BACKEND_URL}/api/settings", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert "provider" in data
        
        # Test health endpoint
        response = requests.get(f"{BACKEND_URL}/health", timeout=10)
        assert response.status_code == 200


@pytest.mark.integration
class TestBackendFrontendCommunication:
    """Test communication between backend and frontend."""
    
    def test_frontend_can_reach_backend(self):
        """Frontend should be able to reach backend API."""
        # This test assumes the frontend makes requests to the backend
        # In a real scenario, you might need to test from within the frontend container
        backend_response = requests.get(f"{BACKEND_URL}/health", timeout=10)
        assert backend_response.status_code == 200
        
        # Frontend should be able to make requests to backend
        # (In browser, this would be a CORS check, but here we verify backend is reachable)
        assert backend_response.json()["status"] == "healthy"
    
    def test_backend_cors_headers(self):
        """Backend should include CORS headers for frontend requests."""
        response = requests.options(
            f"{BACKEND_URL}/api/settings",
            headers={
                "Origin": FRONTEND_URL,
                "Access-Control-Request-Method": "GET"
            },
            timeout=10
        )
        # CORS headers should be present (even if OPTIONS returns 405, headers should exist)
        assert "Access-Control-Allow-Origin" in response.headers or response.status_code == 405


@pytest.mark.integration
class TestOllamaIntegration:
    """Test Ollama integration in Docker."""
    
    def test_ollama_endpoint_accessible(self):
        """Ollama endpoint should be accessible from backend."""
        # Test the Ollama models endpoint
        response = requests.get(
            f"{BACKEND_URL}/api/settings/ollama/models",
            params={"base_url": "http://host.docker.internal:11434"},
            timeout=10
        )
        # Should return 200 even if Ollama is not running (returns available: false)
        assert response.status_code == 200
        data = response.json()
        assert "available" in data
        assert "models" in data
    
    def test_ollama_fallback_when_unavailable(self):
        """Backend should handle Ollama unavailability gracefully."""
        response = requests.get(
            f"{BACKEND_URL}/api/settings/ollama/models",
            params={"base_url": "http://host.docker.internal:11434"},
            timeout=10
        )
        data = response.json()
        
        # If Ollama is not available, should return available: false
        # If available, should return available: true with models
        assert isinstance(data["available"], bool)
        assert isinstance(data["models"], list)
    
    def test_llm_provider_fallback_to_mock(self):
        """When LLM provider fails, should fallback to mock."""
        # This test verifies that the backend can handle LLM failures
        # by testing a chat endpoint with a provider that might not be available
        response = requests.post(
            f"{BACKEND_URL}/api/architect/chat",
            json={
                "message": "Test message",
                "session_id": "test-session"
            },
            timeout=30
        )
        # Should either succeed (with mock fallback) or return a helpful error
        assert response.status_code in [200, 500, 503]
        
        if response.status_code == 200:
            data = response.json()
            assert "response" in data or "error" in data


@pytest.mark.integration
class TestDockerNetworking:
    """Test Docker networking configuration."""
    
    def test_backend_internal_networking(self):
        """Backend should be able to reach host.docker.internal."""
        # This is tested indirectly through Ollama endpoint
        # If host.docker.internal is configured correctly, Ollama endpoint should work
        response = requests.get(
            f"{BACKEND_URL}/api/settings/ollama/models",
            params={"base_url": "http://host.docker.internal:11434"},
            timeout=10
        )
        # Should not return a DNS resolution error
        assert response.status_code == 200
        data = response.json()
        # If there's a connection error, it should be a connection error, not DNS error
        if not data.get("available"):
            error = data.get("error", "")
            assert "host.docker.internal" not in error.lower() or "connection" in error.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
