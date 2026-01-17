"""
LLM Provider - Multi-provider abstraction with minimal boilerplate
Supports: OpenAI, Anthropic, OpenRouter, Gemini, Vertex, Bedrock, Ollama, LM Studio
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


# ===========================================
# Provider Registry
# ===========================================

@dataclass
class ProviderInfo:
    id: str
    name: str
    description: str
    requires_api_key: bool = True
    requires_local: bool = False
    default_model: str = ""
    available_models: List[str] = field(default_factory=list)
    config_fields: List[Dict] = field(default_factory=list)


PROVIDERS: Dict[str, ProviderInfo] = {
    "mock": ProviderInfo("mock", "Mock (Dev)", "Offline mode for development", False, False, "mock-v1", ["mock-v1"], []),
    "openai": ProviderInfo("openai", "OpenAI", "GPT-4 and GPT-3.5 models", True, False, "gpt-4-turbo-preview",
        ["gpt-4-turbo-preview", "gpt-4", "gpt-3.5-turbo"],
        [{"name": "api_key", "label": "API Key", "type": "password", "required": True}, {"name": "model", "label": "Model", "type": "select", "required": True}]),
    "anthropic": ProviderInfo("anthropic", "Anthropic Claude", "Claude 3.5 Sonnet, Opus, Haiku", True, False, "claude-3-5-sonnet-20241022",
        ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
        [{"name": "api_key", "label": "API Key", "type": "password", "required": True}, {"name": "model", "label": "Model", "type": "select", "required": True}]),
    "openrouter": ProviderInfo("openrouter", "OpenRouter", "Access 100+ models via one API", True, False, "anthropic/claude-3.5-sonnet",
        ["anthropic/claude-3.5-sonnet", "openai/gpt-4-turbo", "google/gemini-pro-1.5", "meta-llama/llama-3.1-70b-instruct"],
        [{"name": "api_key", "label": "API Key", "type": "password", "required": True}, {"name": "model", "label": "Model", "type": "select", "required": True}]),
    "gemini": ProviderInfo("gemini", "Google Gemini", "Gemini 1.5 Pro and Flash", True, False, "gemini-1.5-pro",
        ["gemini-1.5-pro", "gemini-1.5-flash"],
        [{"name": "api_key", "label": "Google API Key", "type": "password", "required": True}, {"name": "model", "label": "Model", "type": "select", "required": True}]),
    "vertex": ProviderInfo("vertex", "Vertex AI", "Google Cloud Vertex AI", False, False, "gemini-1.5-pro",
        ["gemini-1.5-pro", "gemini-1.5-flash"],
        [{"name": "project_id", "label": "GCP Project ID", "type": "text", "required": True}, {"name": "location", "label": "Location", "type": "text", "required": True, "default": "us-central1"}]),
    "bedrock": ProviderInfo("bedrock", "AWS Bedrock", "Claude and Titan via AWS", False, False, "anthropic.claude-3-5-sonnet-20241022-v2:0",
        ["anthropic.claude-3-5-sonnet-20241022-v2:0", "amazon.titan-text-express-v1"],
        [{"name": "access_key", "label": "AWS Access Key", "type": "password", "required": True}, {"name": "secret_key", "label": "AWS Secret Key", "type": "password", "required": True}, {"name": "region", "label": "Region", "type": "text", "default": "us-east-1"}]),
    "ollama": ProviderInfo("ollama", "Ollama (Local)", "Run models locally", False, True, "llama3.1",
        ["llama3.1", "mistral", "codellama", "phi3"],
        [{"name": "base_url", "label": "URL", "type": "text", "required": True, "default": "http://localhost:11434"}, {"name": "model", "label": "Model", "type": "text", "required": True}]),
    "lmstudio": ProviderInfo("lmstudio", "LM Studio (Local)", "Local LM Studio server", False, True, "local-model",
        ["local-model"],
        [{"name": "base_url", "label": "URL", "type": "text", "required": True, "default": "http://localhost:1234/v1"}]),
}


# ===========================================
# Base Provider
# ===========================================

class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        pass
    
    async def chat(self, messages: List[Dict], temp: float = 0.7, max_tokens: int = 2000) -> str:
        """Default chat implementation using generate"""
        system = next((m["content"] for m in messages if m["role"] == "system"), None)
        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages if m["role"] != "system")
        return await self.generate(prompt, system, temp, max_tokens)


# ===========================================
# Provider Implementations
# ===========================================

class MockProvider(LLMProvider):
    """Mock provider for development"""
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        p = prompt.lower()
        if "threat" in p or "stride" in p:
            return '{"threats":[{"category":"Spoofing","title":"Auth Bypass","description":"Token manipulation risk","severity":"high","mitigations":["Use strong signing","Validate tokens"]}]}'
        if "compliance" in p:
            return '{"nist_mappings":{"AC-2":"Account Management"},"asvs_mappings":{"V2.1":"Strong passwords"}}'
        if "diagram" in p or "mermaid" in p:
            return "flowchart TB\n  User-->App-->API-->DB"
        return "Mock response - configure real LLM for production"


class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gpt-4-turbo-preview", base_url: str = None):
        self.api_key, self.model, self.base_url = api_key, model, base_url
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url) if self.base_url else AsyncOpenAI(api_key=self.api_key)
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        r = await client.chat.completions.create(model=self.model, messages=msgs, temperature=temp, max_tokens=max_tokens)
        return r.choices[0].message.content


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key, self.model = api_key, model
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        from anthropic import AsyncAnthropic
        r = await AsyncAnthropic(api_key=self.api_key).messages.create(
            model=self.model, max_tokens=max_tokens, temperature=temp,
            system=system or "You are a security analysis assistant.",
            messages=[{"role": "user", "content": prompt}]
        )
        return r.content[0].text


class OpenRouterProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "anthropic/claude-3.5-sonnet"):
        self.api_key, self.model = api_key, model
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=self.api_key, base_url="https://openrouter.ai/api/v1")
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        r = await client.chat.completions.create(model=self.model, messages=msgs, temperature=temp, max_tokens=max_tokens,
            extra_headers={"HTTP-Referer": "https://padmavue.ai"})
        return r.choices[0].message.content


class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gemini-1.5-pro"):
        self.api_key, self.model = api_key, model
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        r = await genai.GenerativeModel(self.model).generate_content_async(
            f"{system}\n\n{prompt}" if system else prompt,
            generation_config={"temperature": temp, "max_output_tokens": max_tokens}
        )
        return r.text


class VertexProvider(LLMProvider):
    def __init__(self, project_id: str, location: str = "us-central1", model: str = "gemini-1.5-pro"):
        self.project_id, self.location, self.model = project_id, location, model
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        import vertexai
        from vertexai.generative_models import GenerativeModel
        vertexai.init(project=self.project_id, location=self.location)
        r = await GenerativeModel(self.model).generate_content_async(
            f"{system}\n\n{prompt}" if system else prompt,
            generation_config={"temperature": temp, "max_output_tokens": max_tokens}
        )
        return r.text


class BedrockProvider(LLMProvider):
    def __init__(self, model_id: str, region: str = "us-east-1", access_key: str = None, secret_key: str = None):
        self.model_id, self.region, self.access_key, self.secret_key = model_id, region, access_key, secret_key
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        import json, boto3
        kw = {"service_name": "bedrock-runtime", "region_name": self.region}
        if self.access_key:
            kw.update(aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)
        body = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": max_tokens, "temperature": temp, "messages": [{"role": "user", "content": prompt}]}
        if system:
            body["system"] = system
        r = boto3.client(**kw).invoke_model(modelId=self.model_id, body=json.dumps(body), contentType="application/json")
        return json.loads(r["body"].read())["content"][0]["text"]


class OllamaProvider(LLMProvider):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.url, self.model = base_url.rstrip("/"), model
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.post(f"{self.url}/api/generate", json={
                "model": self.model, "prompt": f"{system}\n\n{prompt}" if system else prompt,
                "stream": False, "options": {"temperature": temp, "num_predict": max_tokens}
            })
            return r.json()["response"]
    
    async def list_models(self) -> List[str]:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"{self.url}/api/tags")
                return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return []


class LMStudioProvider(LLMProvider):
    def __init__(self, base_url: str = "http://localhost:1234/v1", model: str = None):
        self.url, self.model = base_url.rstrip("/"), model or "local-model"
    
    async def generate(self, prompt: str, system: str = None, temp: float = 0.7, max_tokens: int = 2000) -> str:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key="lm-studio", base_url=self.url)
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        r = await client.chat.completions.create(model=self.model, messages=msgs, temperature=temp, max_tokens=max_tokens)
        return r.choices[0].message.content


# ===========================================
# Factory
# ===========================================

_PROVIDER_MAP = {
    "mock": lambda c: MockProvider(),
    "openai": lambda c: OpenAIProvider(c.get("api_key") or settings.OPENAI_API_KEY, c.get("model") or settings.OPENAI_MODEL, c.get("base_url")),
    "anthropic": lambda c: AnthropicProvider(c.get("api_key") or settings.ANTHROPIC_API_KEY, c.get("model") or settings.ANTHROPIC_MODEL),
    "claude": lambda c: AnthropicProvider(c.get("api_key") or settings.ANTHROPIC_API_KEY, c.get("model") or settings.ANTHROPIC_MODEL),
    "openrouter": lambda c: OpenRouterProvider(c.get("api_key") or settings.OPENROUTER_API_KEY, c.get("model") or settings.OPENROUTER_MODEL),
    "gemini": lambda c: GeminiProvider(c.get("api_key") or settings.GOOGLE_API_KEY, c.get("model") or settings.GOOGLE_MODEL),
    "google": lambda c: GeminiProvider(c.get("api_key") or settings.GOOGLE_API_KEY, c.get("model") or settings.GOOGLE_MODEL),
    "vertex": lambda c: VertexProvider(c.get("project_id") or settings.GOOGLE_CLOUD_PROJECT, c.get("location") or settings.VERTEX_LOCATION, c.get("model") or settings.VERTEX_MODEL),
    "bedrock": lambda c: BedrockProvider(c.get("model") or settings.BEDROCK_MODEL_ID, c.get("region") or settings.AWS_REGION, c.get("access_key") or settings.AWS_ACCESS_KEY_ID, c.get("secret_key") or settings.AWS_SECRET_ACCESS_KEY),
    "aws": lambda c: BedrockProvider(c.get("model") or settings.BEDROCK_MODEL_ID, c.get("region") or settings.AWS_REGION, c.get("access_key") or settings.AWS_ACCESS_KEY_ID, c.get("secret_key") or settings.AWS_SECRET_ACCESS_KEY),
    "ollama": lambda c: OllamaProvider(c.get("base_url") or settings.OLLAMA_BASE_URL, c.get("model") or settings.OLLAMA_MODEL),
    "lmstudio": lambda c: LMStudioProvider(c.get("base_url") or settings.LMSTUDIO_BASE_URL, c.get("model") or settings.LMSTUDIO_MODEL),
}


def get_llm_provider(config: Dict[str, Any] = None) -> LLMProvider:
    """Get configured LLM provider"""
    config = config or {}
    provider = (config.get("provider") or settings.LLM_PROVIDER).lower()
    
    if provider not in _PROVIDER_MAP:
        logger.warning(f"Unknown provider '{provider}', using mock")
        return MockProvider()
    
    try:
        return _PROVIDER_MAP[provider](config)
    except Exception as e:
        logger.warning(f"Failed to init {provider}: {e}, using mock")
        return MockProvider()


def get_provider_info() -> List[Dict]:
    """Get provider info for UI"""
    return [{
        "id": p.id, "name": p.name, "description": p.description,
        "requires_api_key": p.requires_api_key, "requires_local": p.requires_local,
        "default_model": p.default_model, "available_models": p.available_models, "config_fields": p.config_fields
    } for p in PROVIDERS.values()]


# Backward compatibility
PROVIDER_INFO = PROVIDERS
LLMProviderType = type('LLMProviderType', (), {k.upper(): k for k in PROVIDERS})
MockLLMProvider = MockProvider
OpenAIProvider = OpenAIProvider
GoogleGeminiProvider = GeminiProvider
GoogleVertexProvider = VertexProvider
AWSBedrockProvider = BedrockProvider
