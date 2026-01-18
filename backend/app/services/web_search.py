"""
Web Search Service for Grounded Responses
Pluggable search providers with SearXNG (open-source) as default
"""

import httpx
import structlog
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum

from app.config import settings

logger = structlog.get_logger()


# ===========================================
# Data Models
# ===========================================

@dataclass
class SearchResult:
    """A single search result"""
    title: str
    url: str
    snippet: str
    source: Optional[str] = None
    citation_id: Optional[int] = None  # For [1], [2] style citations


@dataclass
class WebGroundedResponse:
    """Response with web grounding and citations"""
    answer: str
    sources: List[SearchResult]
    citations: Dict[int, str]  # {1: "url1", 2: "url2"}
    search_query: str
    provider_used: str
    error: Optional[str] = None


class SearchProviderType(str, Enum):
    """Available search providers"""
    SEARXNG = "searxng"  # Open-source, self-hosted (default)
    TAVILY = "tavily"
    SERPER = "serper"
    BRAVE = "brave"
    BING = "bing"
    MOCK = "mock"
    NONE = "none"


# ===========================================
# Search Provider Interface
# ===========================================

class SearchProvider(ABC):
    """Abstract base class for search providers"""
    
    @abstractmethod
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        """Execute a search query and return results"""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name"""
        pass
    
    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if provider is properly configured"""
        pass
    
    @property
    def requires_api_key(self) -> bool:
        """Whether this provider requires an API key"""
        return True
    
    @property
    def is_open_source(self) -> bool:
        """Whether this is an open-source/self-hosted provider"""
        return False


# ===========================================
# SearXNG Provider (Open-Source Default)
# ===========================================

class SearxngProvider(SearchProvider):
    """
    SearXNG - Open-source metasearch engine (self-hosted)
    Default and recommended provider for privacy-focused search.
    
    Setup: docker run -d -p 8080:8080 searxng/searxng
    Requires JSON format enabled in SearXNG settings.
    """
    
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (base_url or getattr(settings, 'SEARXNG_BASE_URL', None) 
                        or "http://localhost:8080")
    
    @property
    def name(self) -> str:
        return "searxng"
    
    @property
    def requires_api_key(self) -> bool:
        return False  # Self-hosted, no API key needed
    
    @property
    def is_open_source(self) -> bool:
        return True
    
    @property
    def is_configured(self) -> bool:
        return bool(self.base_url)
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        if not self.is_configured:
            logger.warning("SearXNG base URL not configured")
            return []
        
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{self.base_url}/search",
                    params={
                        "q": query,
                        "format": "json",
                        "categories": "general",
                        "language": "en",
                        "pageno": 1
                    }
                )
                
                # Check for JSON format not enabled error
                if response.status_code == 403 or "json" in response.text.lower() and "disabled" in response.text.lower():
                    logger.error("SearXNG JSON format disabled", 
                               hint="Enable JSON format in SearXNG settings.yml: search.formats: [html, json]")
                    return []
                
                response.raise_for_status()
                data = response.json()
                
                results = []
                for i, item in enumerate(data.get("results", [])[:max_results], 1):
                    results.append(SearchResult(
                        title=item.get("title", ""),
                        url=item.get("url", ""),
                        snippet=item.get("content", "")[:500],
                        source=item.get("engine", "SearXNG"),
                        citation_id=i
                    ))
                
                logger.info("SearXNG search complete", 
                           query=query[:50], 
                           results_count=len(results))
                return results
                
        except httpx.ConnectError:
            logger.error("SearXNG not reachable", 
                        base_url=self.base_url,
                        hint="Start SearXNG: docker run -d -p 8080:8080 searxng/searxng")
            return []
        except httpx.HTTPError as e:
            logger.error("SearXNG search failed", error=str(e), query=query[:50])
            return []
        except Exception as e:
            logger.error("SearXNG search error", error=str(e))
            return []


# ===========================================
# Tavily Provider
# ===========================================

class TavilyProvider(SearchProvider):
    """Tavily Search API - optimized for LLM applications"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or getattr(settings, 'TAVILY_API_KEY', None) or settings.SEARCH_API_KEY
        self.base_url = "https://api.tavily.com"
    
    @property
    def name(self) -> str:
        return "tavily"
    
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        if not self.is_configured:
            logger.warning("Tavily API key not configured")
            return []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/search",
                    json={
                        "api_key": self.api_key,
                        "query": query,
                        "search_depth": "basic",
                        "max_results": max_results,
                        "include_answer": False,
                        "include_raw_content": False,
                    }
                )
                response.raise_for_status()
                data = response.json()
                
                results = []
                for i, item in enumerate(data.get("results", [])[:max_results], 1):
                    results.append(SearchResult(
                        title=item.get("title", ""),
                        url=item.get("url", ""),
                        snippet=item.get("content", "")[:500],
                        source=item.get("source", "Tavily"),
                        citation_id=i
                    ))
                
                logger.info("Tavily search complete", query=query[:50], results_count=len(results))
                return results
                
        except httpx.HTTPError as e:
            logger.error("Tavily search failed", error=str(e), query=query[:50])
            return []
        except Exception as e:
            logger.error("Tavily search error", error=str(e))
            return []


# ===========================================
# Serper Provider
# ===========================================

class SerperProvider(SearchProvider):
    """Serper.dev Google Search API"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or getattr(settings, 'SERPER_API_KEY', None) or settings.SEARCH_API_KEY
        self.base_url = "https://google.serper.dev"
    
    @property
    def name(self) -> str:
        return "serper"
    
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        if not self.is_configured:
            logger.warning("Serper API key not configured")
            return []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/search",
                    headers={
                        "X-API-KEY": self.api_key,
                        "Content-Type": "application/json"
                    },
                    json={"q": query, "num": max_results}
                )
                response.raise_for_status()
                data = response.json()
                
                results = []
                for i, item in enumerate(data.get("organic", [])[:max_results], 1):
                    results.append(SearchResult(
                        title=item.get("title", ""),
                        url=item.get("link", ""),
                        snippet=item.get("snippet", "")[:500],
                        source="Google",
                        citation_id=i
                    ))
                
                logger.info("Serper search complete", query=query[:50], results_count=len(results))
                return results
                
        except httpx.HTTPError as e:
            logger.error("Serper search failed", error=str(e), query=query[:50])
            return []
        except Exception as e:
            logger.error("Serper search error", error=str(e))
            return []


# ===========================================
# Brave Search Provider
# ===========================================

class BraveProvider(SearchProvider):
    """Brave Search API - privacy-focused search"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or getattr(settings, 'BRAVE_API_KEY', None) or settings.SEARCH_API_KEY
        self.base_url = "https://api.search.brave.com/res/v1/web/search"
    
    @property
    def name(self) -> str:
        return "brave"
    
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        if not self.is_configured:
            logger.warning("Brave API key not configured")
            return []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.base_url,
                    headers={
                        "X-Subscription-Token": self.api_key,
                        "Accept": "application/json"
                    },
                    params={"q": query, "count": max_results}
                )
                response.raise_for_status()
                data = response.json()
                
                results = []
                web_results = data.get("web", {}).get("results", [])
                for i, item in enumerate(web_results[:max_results], 1):
                    results.append(SearchResult(
                        title=item.get("title", ""),
                        url=item.get("url", ""),
                        snippet=item.get("description", "")[:500],
                        source="Brave",
                        citation_id=i
                    ))
                
                logger.info("Brave search complete", query=query[:50], results_count=len(results))
                return results
                
        except httpx.HTTPError as e:
            logger.error("Brave search failed", error=str(e), query=query[:50])
            return []
        except Exception as e:
            logger.error("Brave search error", error=str(e))
            return []


# ===========================================
# Bing Provider
# ===========================================

class BingProvider(SearchProvider):
    """Bing Search API"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or getattr(settings, 'BING_API_KEY', None) or settings.SEARCH_API_KEY
        self.base_url = "https://api.bing.microsoft.com/v7.0/search"
    
    @property
    def name(self) -> str:
        return "bing"
    
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        if not self.is_configured:
            logger.warning("Bing API key not configured")
            return []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.base_url,
                    headers={"Ocp-Apim-Subscription-Key": self.api_key},
                    params={"q": query, "count": max_results, "responseFilter": "Webpages"}
                )
                response.raise_for_status()
                data = response.json()
                
                results = []
                web_pages = data.get("webPages", {}).get("value", [])
                for i, item in enumerate(web_pages[:max_results], 1):
                    results.append(SearchResult(
                        title=item.get("name", ""),
                        url=item.get("url", ""),
                        snippet=item.get("snippet", "")[:500],
                        source="Bing",
                        citation_id=i
                    ))
                
                logger.info("Bing search complete", query=query[:50], results_count=len(results))
                return results
                
        except httpx.HTTPError as e:
            logger.error("Bing search failed", error=str(e), query=query[:50])
            return []
        except Exception as e:
            logger.error("Bing search error", error=str(e))
            return []


# ===========================================
# DuckDuckGo Provider (Zero-Config Fallback)
# ===========================================

class DuckDuckGoProvider(SearchProvider):
    """
    DuckDuckGo Search - Zero-config, no API key required.
    Uses DuckDuckGo HTML search with basic parsing.
    Serves as automatic fallback when no other provider is configured.
    """
    
    def __init__(self):
        self.base_url = "https://html.duckduckgo.com/html/"
    
    @property
    def name(self) -> str:
        return "duckduckgo"
    
    @property
    def requires_api_key(self) -> bool:
        return False
    
    @property
    def is_open_source(self) -> bool:
        return False  # DDG is not open source, but free to use
    
    @property
    def is_configured(self) -> bool:
        return True  # Always configured - no setup required
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        """
        Search DuckDuckGo by parsing HTML results.
        This is a zero-config fallback that works out of the box.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                response = await client.post(
                    self.base_url,
                    data={"q": query, "b": ""},
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    }
                )
                response.raise_for_status()
                html = response.text
                
                results = []
                
                # Parse results from HTML
                # DuckDuckGo HTML format: <a class="result__a" href="...">title</a>
                # <a class="result__snippet">snippet</a>
                import re
                
                # Find result blocks
                result_pattern = re.compile(
                    r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]*)</a>.*?'
                    r'<a[^>]*class="result__snippet"[^>]*>([^<]*(?:<[^>]*>[^<]*)*)</a>',
                    re.DOTALL | re.IGNORECASE
                )
                
                # Also try simpler pattern for snippet
                simple_pattern = re.compile(
                    r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]*)</a>',
                    re.IGNORECASE
                )
                
                matches = result_pattern.findall(html)
                
                if not matches:
                    # Try simpler extraction
                    matches = simple_pattern.findall(html)
                    for i, match in enumerate(matches[:max_results], 1):
                        url, title = match
                        # Skip DDG tracking URLs
                        if url.startswith('//duckduckgo.com'):
                            continue
                        # Clean up URL
                        if url.startswith('//'):
                            url = 'https:' + url
                        results.append(SearchResult(
                            title=title.strip(),
                            url=url,
                            snippet="",
                            source="DuckDuckGo",
                            citation_id=len(results) + 1
                        ))
                else:
                    for i, match in enumerate(matches[:max_results], 1):
                        url, title, snippet = match
                        # Skip DDG tracking URLs
                        if url.startswith('//duckduckgo.com'):
                            continue
                        # Clean up URL
                        if url.startswith('//'):
                            url = 'https:' + url
                        # Clean HTML from snippet
                        snippet = re.sub(r'<[^>]+>', '', snippet).strip()[:500]
                        results.append(SearchResult(
                            title=title.strip(),
                            url=url,
                            snippet=snippet,
                            source="DuckDuckGo",
                            citation_id=len(results) + 1
                        ))
                
                logger.info("DuckDuckGo search complete", 
                           query=query[:50], 
                           results_count=len(results))
                return results[:max_results]
                
        except httpx.ConnectError:
            logger.error("DuckDuckGo not reachable - check internet connection")
            return []
        except httpx.HTTPError as e:
            logger.error("DuckDuckGo search failed", error=str(e), query=query[:50])
            return []
        except Exception as e:
            logger.error("DuckDuckGo search error", error=str(e))
            return []


# ===========================================
# Mock Provider (Testing)
# ===========================================

class MockProvider(SearchProvider):
    """Mock search provider for testing"""
    
    @property
    def name(self) -> str:
        return "mock"
    
    @property
    def requires_api_key(self) -> bool:
        return False
    
    @property
    def is_configured(self) -> bool:
        return True
    
    async def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        query_lower = query.lower()
        
        # Accurate mock results for common security topics
        if "stride" in query_lower:
            return [
                SearchResult(
                    title="STRIDE Threat Model - Microsoft Learn",
                    url="https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats",
                    snippet="STRIDE is a threat modeling methodology developed by Microsoft. It stands for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. Each category represents a different type of security threat.",
                    source="Microsoft",
                    citation_id=1
                ),
                SearchResult(
                    title="STRIDE (security) - Wikipedia",
                    url="https://en.wikipedia.org/wiki/STRIDE_(security)",
                    snippet="STRIDE is a model for identifying computer security threats developed by Praerit Garg and Loren Kohnfelder at Microsoft. It provides a mnemonic for security threats in six categories. STRIDE is independent of and not related to PASTA methodology.",
                    source="Wikipedia",
                    citation_id=2
                ),
            ]
        elif "pasta" in query_lower:
            return [
                SearchResult(
                    title="PASTA Threat Modeling - OWASP",
                    url="https://owasp.org/www-community/Threat_Modeling_Process",
                    snippet="PASTA (Process for Attack Simulation and Threat Analysis) is a seven-stage risk-centric threat modeling methodology. It is a distinct methodology from STRIDE and focuses on attacker perspective and business impact analysis.",
                    source="OWASP",
                    citation_id=1
                ),
                SearchResult(
                    title="PASTA Threat Modeling Framework",
                    url="https://www.threatmodeler.com/pasta-threat-modeling/",
                    snippet="PASTA is an independent risk-based threat modeling approach with seven stages. It is not related to or part of STRIDE methodology. Stages include: Define Objectives, Define Technical Scope, Application Decomposition, Threat Analysis, Vulnerability Analysis, Attack Modeling, Risk/Impact Analysis.",
                    source="ThreatModeler",
                    citation_id=2
                ),
            ]
        
        return [
            SearchResult(
                title=f"Search results for: {query[:50]}",
                url="https://example.com/search",
                snippet="Mock search result. Configure a real search provider for actual web search. Recommended: SearXNG (self-hosted, open-source).",
                source="Mock",
                citation_id=1
            )
        ]


# ===========================================
# Web Search Service
# ===========================================

class WebSearchService:
    """
    Main service for web searches with caching, citations, and grounding support.
    Defaults to SearXNG (open-source) if configured, otherwise falls back to paid providers.
    """
    
    def __init__(self):
        self._provider: Optional[SearchProvider] = None
        self._cache: Dict[str, List[SearchResult]] = {}
    
    def _create_provider(self, provider_name: str) -> Optional[SearchProvider]:
        """Create a provider instance by name"""
        providers = {
            "searxng": SearxngProvider,
            "tavily": TavilyProvider,
            "serper": SerperProvider,
            "brave": BraveProvider,
            "bing": BingProvider,
            "duckduckgo": DuckDuckGoProvider,
            "mock": MockProvider,
        }
        provider_class = providers.get(provider_name.lower())
        if provider_class:
            return provider_class()
        return None
    
    @property
    def provider(self) -> Optional[SearchProvider]:
        """Get the configured search provider (lazy init)"""
        if self._provider is None:
            provider_name = getattr(settings, 'SEARCH_PROVIDER', 'none').lower()
            
            if provider_name != "none":
                self._provider = self._create_provider(provider_name)
            else:
                # Auto-fallback to DuckDuckGo when no provider configured
                # This enables zero-config web search out of the box
                logger.info("No search provider configured, using DuckDuckGo as fallback")
                self._provider = DuckDuckGoProvider()
        
        return self._provider
    
    def reset_provider(self):
        """Reset provider to force re-initialization"""
        self._provider = None
        self._cache.clear()
    
    @property
    def is_available(self) -> bool:
        """Check if web search is available"""
        return self.provider is not None and self.provider.is_configured
    
    @property
    def provider_name(self) -> str:
        """Get the name of the configured provider"""
        if self.provider:
            return self.provider.name
        return "none"
    
    def get_status(self) -> Dict[str, Any]:
        """Get search service status"""
        provider = self.provider
        configured_provider = getattr(settings, 'SEARCH_PROVIDER', 'none').lower()
        is_fallback = configured_provider == "none" and provider is not None
        
        return {
            "available": self.is_available,
            "provider": self.provider_name,
            "configured": provider.is_configured if provider else False,
            "requires_api_key": provider.requires_api_key if provider else True,
            "is_open_source": provider.is_open_source if provider else False,
            "is_fallback": is_fallback,
            "message": "Using DuckDuckGo (zero-config fallback)" if is_fallback else None,
        }
    
    def get_available_providers(self) -> List[Dict[str, Any]]:
        """Get list of all available search providers with their status"""
        providers = [
            {
                "id": "duckduckgo",
                "name": "DuckDuckGo",
                "description": "Zero-config search, works out of the box (default fallback)",
                "requires_api_key": False,
                "is_open_source": False,
                "config_fields": []
            },
            {
                "id": "searxng",
                "name": "SearXNG",
                "description": "Self-hosted, open-source metasearch engine (recommended for privacy)",
                "requires_api_key": False,
                "is_open_source": True,
                "config_fields": [
                    {"name": "base_url", "label": "SearXNG URL", "type": "text", 
                     "default": "http://localhost:8080", "placeholder": "http://localhost:8080"}
                ]
            },
            {
                "id": "tavily",
                "name": "Tavily",
                "description": "AI-optimized search API",
                "requires_api_key": True,
                "is_open_source": False,
                "config_fields": [
                    {"name": "api_key", "label": "API Key", "type": "password", "placeholder": "tvly-..."}
                ]
            },
            {
                "id": "serper",
                "name": "Serper",
                "description": "Google Search API",
                "requires_api_key": True,
                "is_open_source": False,
                "config_fields": [
                    {"name": "api_key", "label": "API Key", "type": "password", "placeholder": ""}
                ]
            },
            {
                "id": "brave",
                "name": "Brave Search",
                "description": "Privacy-focused search API",
                "requires_api_key": True,
                "is_open_source": False,
                "config_fields": [
                    {"name": "api_key", "label": "API Key", "type": "password", "placeholder": "BSA..."}
                ]
            },
            {
                "id": "bing",
                "name": "Bing",
                "description": "Microsoft Bing Search API",
                "requires_api_key": True,
                "is_open_source": False,
                "config_fields": [
                    {"name": "api_key", "label": "API Key", "type": "password", "placeholder": ""}
                ]
            },
        ]
        return providers
    
    async def search(
        self, 
        query: str, 
        max_results: int = None,
        use_cache: bool = True
    ) -> List[SearchResult]:
        """
        Execute a web search with optional caching.
        """
        if not self.is_available:
            logger.warning("Web search not available", provider=self.provider_name)
            return []
        
        max_results = max_results or getattr(settings, 'SEARCH_MAX_RESULTS', 5)
        cache_key = f"{query}:{max_results}"
        
        # Check cache
        if use_cache and cache_key in self._cache:
            logger.debug("Using cached search results", query=query[:50])
            return self._cache[cache_key]
        
        # Execute search
        results = await self.provider.search(query, max_results)
        
        # Assign citation IDs if not set
        for i, result in enumerate(results, 1):
            if result.citation_id is None:
                result.citation_id = i
        
        # Cache results
        if results:
            self._cache[cache_key] = results
        
        return results
    
    async def search_with_grounding(
        self,
        query: str,
        max_results: int = 5
    ) -> WebGroundedResponse:
        """
        Perform a search and return a grounded response structure with citations.
        """
        results = await self.search(query, max_results, use_cache=True)
        
        if not results:
            return WebGroundedResponse(
                answer="",
                sources=[],
                citations={},
                search_query=query,
                provider_used=self.provider_name,
                error="No search results found" if self.is_available else "Search provider not configured"
            )
        
        # Build citations map
        citations = {r.citation_id: r.url for r in results if r.citation_id}
        
        return WebGroundedResponse(
            answer="",  # To be filled by LLM
            sources=results,
            citations=citations,
            search_query=query,
            provider_used=self.provider_name
        )
    
    def clear_cache(self):
        """Clear the search cache"""
        self._cache.clear()
    
    def format_sources_for_llm(self, results: List[SearchResult]) -> str:
        """Format search results as context for LLM"""
        if not results:
            return ""
        
        context = "\n\n## Web Search Results:\n"
        for result in results:
            context += f"\n### [{result.citation_id}] {result.title}\n"
            context += f"URL: {result.url}\n"
            context += f"Content: {result.snippet}\n"
        
        return context
    
    def format_sources_for_response(self, results: List[SearchResult]) -> str:
        """Format search results as a Sources section for display"""
        if not results:
            return ""
        
        sources = "\n\n**Sources:**\n"
        for result in results:
            sources += f"[{result.citation_id}] [{result.title}]({result.url})\n"
        
        return sources


# Global service instance
web_search_service = WebSearchService()


def get_web_search_service() -> WebSearchService:
    """Get the global web search service instance"""
    return web_search_service
