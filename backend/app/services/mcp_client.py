"""
MCP (Model Context Protocol) Client Service
Universal client for connecting to external MCP servers
"""

import json
import asyncio
import httpx
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class MCPTransport(str, Enum):
    """Supported MCP transport types"""
    HTTP = "http"           # Streamable HTTP (recommended for remote)
    SSE = "sse"             # Server-Sent Events
    STDIO = "stdio"         # Standard I/O (for local servers)


class MCPAuthType(str, Enum):
    """Authentication types for MCP servers"""
    NONE = "none"
    API_KEY = "api_key"
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    BASIC = "basic"


@dataclass
class MCPTool:
    """Represents a tool discovered from an MCP server"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    server_id: str


@dataclass
class MCPResource:
    """Represents a resource from an MCP server"""
    uri: str
    name: str
    description: str
    mime_type: Optional[str]
    server_id: str


@dataclass
class MCPPrompt:
    """Represents a prompt template from an MCP server"""
    name: str
    description: str
    arguments: List[Dict[str, Any]]
    server_id: str


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server connection"""
    id: str
    name: str
    uri: str
    transport: MCPTransport = MCPTransport.HTTP
    auth_type: MCPAuthType = MCPAuthType.NONE
    auth_credentials: Optional[Dict[str, str]] = None
    enabled: bool = True
    description: Optional[str] = None
    tags: List[str] = None
    created_at: str = None
    updated_at: str = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat()
        if self.updated_at is None:
            self.updated_at = self.created_at


class MCPClient:
    """
    Universal MCP Client for PadmaVue.ai
    
    Connects to external MCP servers to discover and invoke security tools,
    access knowledge resources, and use prompt templates.
    """
    
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.client: Optional[httpx.AsyncClient] = None
        self.tools: List[MCPTool] = []
        self.resources: List[MCPResource] = []
        self.prompts: List[MCPPrompt] = []
        self.connected = False
        self._request_id = 0
    
    def _next_request_id(self) -> int:
        """Generate next request ID for JSON-RPC"""
        self._request_id += 1
        return self._request_id
    
    def _get_headers(self) -> Dict[str, str]:
        """Build headers based on auth configuration"""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        if self.config.auth_type == MCPAuthType.BEARER and self.config.auth_credentials:
            token = self.config.auth_credentials.get("token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif self.config.auth_type == MCPAuthType.API_KEY and self.config.auth_credentials:
            api_key = self.config.auth_credentials.get("api_key")
            header_name = self.config.auth_credentials.get("header_name", "X-API-Key")
            if api_key:
                headers[header_name] = api_key
        
        return headers
    
    async def connect(self) -> bool:
        """Establish connection to MCP server"""
        try:
            self.client = httpx.AsyncClient(
                base_url=self.config.uri,
                headers=self._get_headers(),
                timeout=30.0
            )
            
            # Perform initialization handshake
            response = await self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "clientInfo": {
                    "name": "PadmaVue.ai",
                    "version": "1.0.0"
                }
            })
            
            if response.get("result"):
                self.connected = True
                logger.info("mcp_connected", server=self.config.name, uri=self.config.uri)
                
                # Send initialized notification
                await self._send_notification("notifications/initialized")
                
                # Discover capabilities
                await self.discover_all()
                return True
            
            return False
            
        except Exception as e:
            logger.error("mcp_connect_failed", server=self.config.name, error=str(e))
            self.connected = False
            return False
    
    async def disconnect(self):
        """Close connection to MCP server"""
        if self.client:
            await self.client.aclose()
            self.client = None
            self.connected = False
            logger.info("mcp_disconnected", server=self.config.name)
    
    async def _send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send JSON-RPC request to MCP server"""
        if not self.client:
            raise RuntimeError("MCP client not connected")
        
        request = {
            "jsonrpc": "2.0",
            "id": self._next_request_id(),
            "method": method,
        }
        if params:
            request["params"] = params
        
        try:
            response = await self.client.post("/", json=request)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("mcp_request_failed", method=method, error=str(e))
            raise
    
    async def _send_notification(self, method: str, params: Dict[str, Any] = None):
        """Send JSON-RPC notification (no response expected)"""
        if not self.client:
            return
        
        notification = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            notification["params"] = params
        
        try:
            await self.client.post("/", json=notification)
        except Exception:
            pass  # Notifications don't require response
    
    async def discover_all(self):
        """Discover all capabilities from the server"""
        await asyncio.gather(
            self.list_tools(),
            self.list_resources(),
            self.list_prompts(),
            return_exceptions=True
        )
    
    async def list_tools(self) -> List[MCPTool]:
        """Discover available tools from MCP server"""
        try:
            response = await self._send_request("tools/list")
            result = response.get("result", {})
            tools_data = result.get("tools", [])
            
            self.tools = [
                MCPTool(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                    server_id=self.config.id
                )
                for t in tools_data
            ]
            
            logger.info("mcp_tools_discovered", server=self.config.name, count=len(self.tools))
            return self.tools
            
        except Exception as e:
            logger.error("mcp_list_tools_failed", error=str(e))
            return []
    
    async def list_resources(self) -> List[MCPResource]:
        """Discover available resources from MCP server"""
        try:
            response = await self._send_request("resources/list")
            result = response.get("result", {})
            resources_data = result.get("resources", [])
            
            self.resources = [
                MCPResource(
                    uri=r["uri"],
                    name=r.get("name", r["uri"]),
                    description=r.get("description", ""),
                    mime_type=r.get("mimeType"),
                    server_id=self.config.id
                )
                for r in resources_data
            ]
            
            logger.info("mcp_resources_discovered", server=self.config.name, count=len(self.resources))
            return self.resources
            
        except Exception as e:
            logger.error("mcp_list_resources_failed", error=str(e))
            return []
    
    async def list_prompts(self) -> List[MCPPrompt]:
        """Discover available prompts from MCP server"""
        try:
            response = await self._send_request("prompts/list")
            result = response.get("result", {})
            prompts_data = result.get("prompts", [])
            
            self.prompts = [
                MCPPrompt(
                    name=p["name"],
                    description=p.get("description", ""),
                    arguments=p.get("arguments", []),
                    server_id=self.config.id
                )
                for p in prompts_data
            ]
            
            logger.info("mcp_prompts_discovered", server=self.config.name, count=len(self.prompts))
            return self.prompts
            
        except Exception as e:
            logger.error("mcp_list_prompts_failed", error=str(e))
            return []
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke a tool on the MCP server
        
        Args:
            tool_name: Name of the tool to invoke
            arguments: Tool input arguments
            
        Returns:
            Tool execution result
        """
        logger.info("mcp_tool_call", server=self.config.name, tool=tool_name)
        
        try:
            response = await self._send_request("tools/call", {
                "name": tool_name,
                "arguments": arguments
            })
            
            result = response.get("result", {})
            content = result.get("content", [])
            
            logger.info("mcp_tool_result", tool=tool_name, success=not result.get("isError", False))
            
            return {
                "success": not result.get("isError", False),
                "content": content,
                "error": result.get("error")
            }
            
        except Exception as e:
            logger.error("mcp_tool_call_failed", tool=tool_name, error=str(e))
            return {"success": False, "error": str(e)}
    
    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource from the MCP server"""
        try:
            response = await self._send_request("resources/read", {"uri": uri})
            result = response.get("result", {})
            contents = result.get("contents", [])
            
            return {
                "success": True,
                "contents": contents
            }
            
        except Exception as e:
            logger.error("mcp_resource_read_failed", uri=uri, error=str(e))
            return {"success": False, "error": str(e)}
    
    async def get_prompt(self, name: str, arguments: Dict[str, str] = None) -> Dict[str, Any]:
        """Get a prompt from the MCP server"""
        try:
            params = {"name": name}
            if arguments:
                params["arguments"] = arguments
                
            response = await self._send_request("prompts/get", params)
            result = response.get("result", {})
            
            return {
                "success": True,
                "description": result.get("description"),
                "messages": result.get("messages", [])
            }
            
        except Exception as e:
            logger.error("mcp_prompt_get_failed", name=name, error=str(e))
            return {"success": False, "error": str(e)}


class MCPServerManager:
    """
    Manages multiple MCP server connections
    
    Provides a unified interface to discover and invoke tools
    across all connected MCP servers.
    """
    
    CONFIG_FILE = Path("data/mcp_servers.json")
    
    def __init__(self):
        self.servers: Dict[str, MCPClient] = {}
        self.configs: Dict[str, MCPServerConfig] = {}
    
    async def load_configs(self):
        """Load server configurations from persistent storage"""
        if self.CONFIG_FILE.exists():
            try:
                data = json.loads(self.CONFIG_FILE.read_text())
                for item in data:
                    # Convert string enums back to enum types if needed
                    if 'transport' in item and isinstance(item['transport'], str):
                        item['transport'] = MCPTransport(item['transport'])
                    if 'auth_type' in item and isinstance(item['auth_type'], str):
                        item['auth_type'] = MCPAuthType(item['auth_type'])
                    config = MCPServerConfig(**item)
                    self.configs[config.id] = config
                logger.info("mcp_configs_loaded", count=len(self.configs))
            except Exception as e:
                logger.error("mcp_configs_load_failed", error=str(e))
    
    def save_configs(self):
        """Save server configurations to persistent storage"""
        self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        data = [asdict(c) for c in self.configs.values()]
        self.CONFIG_FILE.write_text(json.dumps(data, indent=2, default=str))
        logger.info("mcp_configs_saved", count=len(self.configs))
    
    async def add_server(self, config: MCPServerConfig) -> bool:
        """Add and connect to a new MCP server"""
        self.configs[config.id] = config
        self.save_configs()
        
        if config.enabled:
            return await self.connect_server(config.id)
        return True
    
    async def remove_server(self, server_id: str):
        """Remove an MCP server"""
        if server_id in self.servers:
            await self.servers[server_id].disconnect()
            del self.servers[server_id]
        
        if server_id in self.configs:
            del self.configs[server_id]
            self.save_configs()
    
    async def connect_server(self, server_id: str) -> bool:
        """Connect to a specific MCP server"""
        config = self.configs.get(server_id)
        if not config:
            return False
        
        client = MCPClient(config)
        success = await client.connect()
        
        if success:
            self.servers[server_id] = client
        
        return success
    
    async def disconnect_server(self, server_id: str):
        """Disconnect from a specific MCP server"""
        if server_id in self.servers:
            await self.servers[server_id].disconnect()
            del self.servers[server_id]
    
    async def connect_all(self):
        """Connect to all enabled MCP servers"""
        await self.load_configs()
        
        for config in self.configs.values():
            if config.enabled:
                await self.connect_server(config.id)
    
    async def disconnect_all(self):
        """Disconnect from all MCP servers"""
        for server_id in list(self.servers.keys()):
            await self.disconnect_server(server_id)
    
    def get_all_tools(self) -> List[MCPTool]:
        """Get all tools from all connected servers"""
        tools = []
        for client in self.servers.values():
            tools.extend(client.tools)
        return tools
    
    def get_all_resources(self) -> List[MCPResource]:
        """Get all resources from all connected servers"""
        resources = []
        for client in self.servers.values():
            resources.extend(client.resources)
        return resources
    
    def get_all_prompts(self) -> List[MCPPrompt]:
        """Get all prompts from all connected servers"""
        prompts = []
        for client in self.servers.values():
            prompts.extend(client.prompts)
        return prompts
    
    def get_tools_for_llm(self) -> List[Dict[str, Any]]:
        """
        Convert MCP tools to OpenAI-compatible function format
        for LLM tool calling
        """
        llm_tools = []
        
        for tool in self.get_all_tools():
            llm_tools.append({
                "type": "function",
                "function": {
                    "name": f"mcp_{tool.server_id}_{tool.name}",
                    "description": tool.description,
                    "parameters": tool.input_schema
                }
            })
        
        return llm_tools
    
    async def call_tool(self, server_id: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on a specific server"""
        client = self.servers.get(server_id)
        if not client:
            return {"success": False, "error": f"Server {server_id} not connected"}
        
        return await client.call_tool(tool_name, arguments)
    
    async def test_connection(self, uri: str, transport: str = "http", 
                             auth_type: str = "none", 
                             auth_credentials: Dict[str, str] = None) -> Dict[str, Any]:
        """Test connection to an MCP server without persisting"""
        config = MCPServerConfig(
            id="test",
            name="Test Connection",
            uri=uri,
            transport=MCPTransport(transport),
            auth_type=MCPAuthType(auth_type),
            auth_credentials=auth_credentials
        )
        
        client = MCPClient(config)
        
        try:
            success = await client.connect()
            
            if success:
                result = {
                    "success": True,
                    "server_info": {
                        "tools_count": len(client.tools),
                        "resources_count": len(client.resources),
                        "prompts_count": len(client.prompts),
                        "tools": [{"name": t.name, "description": t.description} for t in client.tools[:5]],
                        "resources": [{"name": r.name, "uri": r.uri} for r in client.resources[:5]],
                    }
                }
                await client.disconnect()
                return result
            else:
                return {"success": False, "error": "Failed to initialize connection"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}


# Global manager instance
mcp_manager = MCPServerManager()

