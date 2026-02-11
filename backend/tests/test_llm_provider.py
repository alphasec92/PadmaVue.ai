"""
LLM Provider tests.

Tests:
1. LLM provider initialization
2. Mock provider functionality
3. Ollama provider connection handling
4. Error handling and fallback
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import httpx

from app.services.llm_provider import (
    get_llm_provider,
    MockProvider,
    OllamaProvider,
    OpenAIProvider,
    AnthropicProvider
)


class TestGetLLMProvider:
    """Test LLM provider factory function."""
    
    def test_get_mock_provider(self):
        """Should return MockProvider for mock config."""
        config = {"provider": "mock"}
        provider = get_llm_provider(config)
        assert isinstance(provider, MockProvider)
    
    def test_get_ollama_provider(self):
        """Should return OllamaProvider for ollama config."""
        config = {
            "provider": "ollama",
            "base_url": "http://localhost:11434",
            "model": "llama3.1"
        }
        provider = get_llm_provider(config)
        assert isinstance(provider, OllamaProvider)
        assert provider.url == "http://localhost:11434"
        assert provider.model == "llama3.1"
    
    def test_get_openai_provider(self):
        """Should return OpenAIProvider for openai config."""
        config = {
            "provider": "openai",
            "api_key": "test-key",
            "model": "gpt-4"
        }
        provider = get_llm_provider(config)
        assert isinstance(provider, OpenAIProvider)
    
    def test_get_anthropic_provider(self):
        """Should return AnthropicProvider for anthropic config."""
        config = {
            "provider": "anthropic",
            "api_key": "test-key",
            "model": "claude-3-opus-20240229"
        }
        provider = get_llm_provider(config)
        assert isinstance(provider, AnthropicProvider)
    
    def test_default_to_mock_when_no_provider(self):
        """Should default to MockProvider when no provider specified."""
        config = {}
        provider = get_llm_provider(config)
        assert isinstance(provider, MockProvider)
    
    def test_default_to_mock_when_invalid_provider(self):
        """Should default to MockProvider when invalid provider specified."""
        config = {"provider": "invalid_provider"}
        provider = get_llm_provider(config)
        assert isinstance(provider, MockProvider)


class TestMockProvider:
    """Test MockProvider functionality."""
    
    @pytest.fixture
    def mock_provider(self):
        """Create a MockProvider instance."""
        return MockProvider()
    
    @pytest.mark.asyncio
    async def test_mock_provider_generate(self, mock_provider):
        """MockProvider.generate should return a response."""
        response = await mock_provider.generate("Test prompt")
        assert isinstance(response, str)
        assert len(response) > 0
    
    @pytest.mark.asyncio
    async def test_mock_provider_chat(self, mock_provider):
        """MockProvider.chat should return a response."""
        messages = [
            {"role": "system", "content": "You are a security expert."},
            {"role": "user", "content": "What are common threats?"}
        ]
        response = await mock_provider.chat(messages)
        assert isinstance(response, str)
        assert len(response) > 0
    
    @pytest.mark.asyncio
    async def test_mock_provider_list_models(self, mock_provider):
        """MockProvider.list_models should return a list."""
        models = await mock_provider.list_models()
        assert isinstance(models, list)
        assert len(models) > 0


class TestOllamaProvider:
    """Test OllamaProvider functionality."""
    
    @pytest.fixture
    def ollama_provider(self):
        """Create an OllamaProvider instance."""
        return OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_ollama_provider_generate_success(self, mock_client_class, ollama_provider):
        """OllamaProvider.generate should handle successful requests."""
        # Mock successful HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {"response": "Test response"}
        mock_response.raise_for_status = MagicMock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client
        
        response = await ollama_provider.generate("Test prompt")
        assert response == "Test response"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_ollama_provider_generate_connection_error(self, mock_client_class, ollama_provider):
        """OllamaProvider.generate should raise ConnectionError on connection failure."""
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client
        
        with pytest.raises(ConnectionError) as exc_info:
            await ollama_provider.generate("Test prompt")
        assert "Cannot connect to Ollama" in str(exc_info.value)
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_ollama_provider_generate_timeout(self, mock_client_class, ollama_provider):
        """OllamaProvider.generate should raise TimeoutError on timeout."""
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.TimeoutException("Request timed out")
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client
        
        with pytest.raises(TimeoutError) as exc_info:
            await ollama_provider.generate("Test prompt")
        assert "timed out" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_ollama_provider_list_models_success(self, mock_client_class, ollama_provider):
        """OllamaProvider.list_models should return list of models."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "models": [
                {"name": "llama3.1"},
                {"name": "mistral"},
                {"name": "codellama"}
            ]
        }
        
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client
        
        models = await ollama_provider.list_models()
        assert isinstance(models, list)
        assert len(models) == 3
        assert "llama3.1" in models
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_ollama_provider_list_models_error(self, mock_client_class, ollama_provider):
        """OllamaProvider.list_models should return empty list on error."""
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Connection error")
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client
        
        models = await ollama_provider.list_models()
        assert isinstance(models, list)
        assert len(models) == 0


class TestProviderErrorHandling:
    """Test error handling across providers."""
    
    @pytest.mark.asyncio
    async def test_mock_provider_never_fails(self):
        """MockProvider should never raise exceptions."""
        provider = MockProvider()
        
        # All methods should work without errors
        response = await provider.generate("test")
        assert response is not None
        
        chat_response = await provider.chat([{"role": "user", "content": "test"}])
        assert chat_response is not None
        
        models = await provider.list_models()
        assert models is not None
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_ollama_provider_handles_http_errors(self, mock_client_class):
        """OllamaProvider should handle HTTP status errors."""
        provider = OllamaProvider()
        
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Request",
            request=MagicMock(),
            response=mock_response
        )
        mock_response.status_code = 400
        mock_response.text = "Invalid model"
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_class.return_value = mock_client
        
        with pytest.raises(RuntimeError) as exc_info:
            await provider.generate("test")
        assert "Ollama API error" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
