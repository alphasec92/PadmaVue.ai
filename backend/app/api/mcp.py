"""
MCP (Model Context Protocol) API Endpoints
Manage external MCP server connections
"""

import json
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime

from app.services.mcp_client import (
    mcp_manager,
    MCPServerConfig,
    MCPTransport,
    MCPAuthType,
)

router = APIRouter()


# ============== Pre-configured MCP Server Registry ==============
# Popular MCP servers from the ecosystem
# Sources: https://github.com/modelcontextprotocol, Docker Hub MCP

MCP_SERVER_REGISTRY = [
    # Official MCP Servers
    {
        "id": "mcp-memory",
        "name": "Memory Server",
        "description": "Persistent memory storage for AI context across sessions",
        "category": "Core",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory"]
        },
        "tags": ["memory", "persistence", "context"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/memory"
    },
    {
        "id": "mcp-filesystem",
        "name": "Filesystem Server",
        "description": "Secure file system access with configurable permissions",
        "category": "Core",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/directory"]
        },
        "tags": ["filesystem", "files", "io"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem"
    },
    {
        "id": "mcp-github",
        "name": "GitHub Server",
        "description": "GitHub repository access, issues, PRs, and code search",
        "category": "Developer Tools",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": ""}
        },
        "requires_auth": True,
        "auth_fields": [{"name": "GITHUB_PERSONAL_ACCESS_TOKEN", "label": "GitHub PAT", "type": "password"}],
        "tags": ["github", "git", "code", "security"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/github"
    },
    {
        "id": "mcp-gitlab",
        "name": "GitLab Server",
        "description": "GitLab repository access and CI/CD integration",
        "category": "Developer Tools",
        "source": "community",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-gitlab"],
            "env": {"GITLAB_PERSONAL_ACCESS_TOKEN": "", "GITLAB_API_URL": "https://gitlab.com/api/v4"}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "GITLAB_PERSONAL_ACCESS_TOKEN", "label": "GitLab PAT", "type": "password"},
            {"name": "GITLAB_API_URL", "label": "GitLab API URL", "type": "text", "default": "https://gitlab.com/api/v4"}
        ],
        "tags": ["gitlab", "git", "ci/cd"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/gitlab"
    },
    {
        "id": "mcp-postgres",
        "name": "PostgreSQL Server",
        "description": "Read-only PostgreSQL database access with schema inspection",
        "category": "Databases",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres"],
            "env": {"POSTGRES_CONNECTION_STRING": ""}
        },
        "requires_auth": True,
        "auth_fields": [{"name": "POSTGRES_CONNECTION_STRING", "label": "Connection String", "type": "password"}],
        "tags": ["database", "postgres", "sql"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/postgres"
    },
    {
        "id": "mcp-sqlite",
        "name": "SQLite Server",
        "description": "SQLite database access for local data analysis",
        "category": "Databases",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-sqlite", "--db-path", "/path/to/database.db"]
        },
        "tags": ["database", "sqlite", "sql", "local"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite"
    },
    {
        "id": "mcp-puppeteer",
        "name": "Puppeteer Server",
        "description": "Browser automation for web scraping and testing",
        "category": "Web",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-puppeteer"]
        },
        "tags": ["browser", "automation", "web", "testing"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer"
    },
    {
        "id": "mcp-brave-search",
        "name": "Brave Search Server",
        "description": "Web search using Brave Search API",
        "category": "Search",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-brave-search"],
            "env": {"BRAVE_API_KEY": ""}
        },
        "requires_auth": True,
        "auth_fields": [{"name": "BRAVE_API_KEY", "label": "Brave API Key", "type": "password"}],
        "tags": ["search", "web", "brave"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search"
    },
    {
        "id": "mcp-fetch",
        "name": "Fetch Server",
        "description": "HTTP request capabilities for fetching web content",
        "category": "Web",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-fetch"]
        },
        "tags": ["http", "web", "api", "fetch"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch"
    },
    {
        "id": "mcp-slack",
        "name": "Slack Server",
        "description": "Slack workspace integration for messaging and search",
        "category": "Communication",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-slack"],
            "env": {"SLACK_BOT_TOKEN": "", "SLACK_TEAM_ID": ""}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "SLACK_BOT_TOKEN", "label": "Bot Token", "type": "password"},
            {"name": "SLACK_TEAM_ID", "label": "Team ID", "type": "text"}
        ],
        "tags": ["slack", "messaging", "communication"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/slack"
    },
    {
        "id": "mcp-google-drive",
        "name": "Google Drive Server",
        "description": "Google Drive file access and search",
        "category": "Cloud Storage",
        "source": "official",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-gdrive"]
        },
        "requires_auth": True,
        "tags": ["google", "drive", "files", "cloud"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/gdrive"
    },
    # Security-focused servers
    {
        "id": "mcp-snyk",
        "name": "Snyk Security",
        "description": "Security vulnerability scanning and dependency analysis",
        "category": "Security",
        "source": "community",
        "config": {
            "transport": "http",
            "url": "https://api.snyk.io/mcp",
            "headers": {"Authorization": "Bearer "}
        },
        "requires_auth": True,
        "auth_fields": [{"name": "Authorization", "label": "Snyk API Token", "type": "password"}],
        "tags": ["security", "vulnerabilities", "sca", "snyk"],
        "docs_url": "https://docs.snyk.io"
    },
    {
        "id": "mcp-aws",
        "name": "AWS Server",
        "description": "AWS service access via MCP (requires awslabs/mcp)",
        "category": "Cloud",
        "source": "community",
        "config": {
            "transport": "stdio",
            "command": "python",
            "args": ["-m", "awslabs.mcp"]
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "AWS_ACCESS_KEY_ID", "label": "AWS Access Key", "type": "text"},
            {"name": "AWS_SECRET_ACCESS_KEY", "label": "AWS Secret Key", "type": "password"},
            {"name": "AWS_REGION", "label": "AWS Region", "type": "text", "default": "us-east-1"}
        ],
        "tags": ["aws", "cloud", "infrastructure"],
        "docs_url": "https://github.com/awslabs/mcp"
    },
    {
        "id": "mcp-context7",
        "name": "Context7",
        "description": "Up-to-date documentation for popular libraries and frameworks",
        "category": "Documentation",
        "source": "community",
        "config": {
            "transport": "http",
            "url": "https://mcp.context7.com/mcp"
        },
        "tags": ["docs", "documentation", "libraries"],
        "docs_url": "https://context7.com"
    },
    {
        "id": "mcp-sentry",
        "name": "Sentry Server",
        "description": "Error tracking and performance monitoring",
        "category": "Observability",
        "source": "community",
        "config": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-sentry"],
            "env": {"SENTRY_AUTH_TOKEN": "", "SENTRY_ORG": ""}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "SENTRY_AUTH_TOKEN", "label": "Auth Token", "type": "password"},
            {"name": "SENTRY_ORG", "label": "Organization", "type": "text"}
        ],
        "tags": ["sentry", "errors", "monitoring"],
        "docs_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/sentry"
    },
    # Docker Hub MCP servers
    {
        "id": "docker-mcp-time",
        "name": "Time Server (Docker)",
        "description": "Time and timezone utilities via Docker",
        "category": "Utilities",
        "source": "docker",
        "config": {
            "transport": "stdio",
            "command": "docker",
            "args": ["run", "-i", "--rm", "mcp/time"]
        },
        "tags": ["time", "timezone", "docker"],
        "docs_url": "https://hub.docker.com/r/mcp/time"
    },
    {
        "id": "docker-mcp-fetch",
        "name": "Fetch Server (Docker)",
        "description": "HTTP fetch server running in Docker container",
        "category": "Web",
        "source": "docker",
        "config": {
            "transport": "stdio",
            "command": "docker",
            "args": ["run", "-i", "--rm", "mcp/fetch"]
        },
        "tags": ["http", "web", "docker"],
        "docs_url": "https://hub.docker.com/r/mcp/fetch"
    },
    # Atlassian
    {
        "id": "mcp-atlassian-jira",
        "name": "Atlassian Jira",
        "description": "Jira issue tracking, project management, and sprint boards",
        "category": "Project Management",
        "source": "community",
        "config": {
            "transport": "http",
            "url": "https://api.atlassian.com/mcp",
            "headers": {"Authorization": "Bearer "}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "Authorization", "label": "Atlassian API Token", "type": "password"},
            {"name": "X-Atlassian-Site", "label": "Site URL (e.g., yoursite.atlassian.net)", "type": "text"}
        ],
        "tags": ["jira", "atlassian", "issues", "project-management"],
        "docs_url": "https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/"
    },
    {
        "id": "mcp-atlassian-confluence",
        "name": "Atlassian Confluence",
        "description": "Confluence wiki, documentation, and knowledge base",
        "category": "Documentation",
        "source": "community",
        "config": {
            "transport": "http",
            "url": "https://api.atlassian.com/mcp/confluence",
            "headers": {"Authorization": "Bearer "}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "Authorization", "label": "Atlassian API Token", "type": "password"},
            {"name": "X-Atlassian-Site", "label": "Site URL", "type": "text"}
        ],
        "tags": ["confluence", "atlassian", "wiki", "documentation"],
        "docs_url": "https://developer.atlassian.com/cloud/confluence/rest/v2/intro/"
    },
    {
        "id": "mcp-atlassian-bitbucket",
        "name": "Atlassian Bitbucket",
        "description": "Bitbucket repositories, pull requests, and pipelines",
        "category": "Developer Tools",
        "source": "community",
        "config": {
            "transport": "http",
            "url": "https://api.bitbucket.org/2.0/mcp",
            "headers": {"Authorization": "Bearer "}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "Authorization", "label": "Bitbucket App Password", "type": "password"},
            {"name": "X-Workspace", "label": "Workspace ID", "type": "text"}
        ],
        "tags": ["bitbucket", "atlassian", "git", "ci/cd"],
        "docs_url": "https://developer.atlassian.com/cloud/bitbucket/rest/intro/"
    },
    # ServiceNow
    {
        "id": "mcp-servicenow",
        "name": "ServiceNow",
        "description": "ServiceNow ITSM - incidents, changes, problems, and CMDB",
        "category": "ITSM",
        "source": "community",
        "config": {
            "transport": "http",
            "url": "",
            "headers": {"Authorization": "Basic "}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "instance_url", "label": "Instance URL (e.g., https://dev12345.service-now.com)", "type": "text"},
            {"name": "username", "label": "Username", "type": "text"},
            {"name": "password", "label": "Password", "type": "password"}
        ],
        "tags": ["servicenow", "itsm", "incidents", "cmdb"],
        "docs_url": "https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/"
    },
    {
        "id": "mcp-servicenow-security",
        "name": "ServiceNow Security Operations",
        "description": "ServiceNow SecOps - security incidents, vulnerabilities, and threat intelligence",
        "category": "Security",
        "source": "community",
        "config": {
            "transport": "http",
            "url": "",
            "headers": {"Authorization": "Basic "}
        },
        "requires_auth": True,
        "auth_fields": [
            {"name": "instance_url", "label": "Instance URL", "type": "text"},
            {"name": "username", "label": "Username", "type": "text"},
            {"name": "password", "label": "Password", "type": "password"}
        ],
        "tags": ["servicenow", "secops", "security", "vulnerabilities"],
        "docs_url": "https://docs.servicenow.com/bundle/latest/page/product/security-operations/concept/security-operations.html"
    }
]


# ============== Pydantic Models ==============

class MCPServerCreate(BaseModel):
    """Request to add a new MCP server"""
    name: str = Field(..., min_length=1, max_length=100)
    uri: str = Field(..., description="Server URL (e.g., https://api.example.com/mcp)")
    transport: str = Field(default="http", description="Transport type: http, sse, stdio")
    auth_type: str = Field(default="none", description="Auth type: none, api_key, bearer, oauth2")
    auth_credentials: Optional[Dict[str, str]] = Field(default=None, description="Auth credentials")
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    enabled: bool = True


class MCPServerUpdate(BaseModel):
    """Request to update an MCP server"""
    name: Optional[str] = None
    uri: Optional[str] = None
    transport: Optional[str] = None
    auth_type: Optional[str] = None
    auth_credentials: Optional[Dict[str, str]] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None


class MCPToolCallRequest(BaseModel):
    """Request to call an MCP tool"""
    server_id: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class MCPTestConnectionRequest(BaseModel):
    """Request to test MCP server connection"""
    uri: str
    transport: str = "http"
    auth_type: str = "none"
    auth_credentials: Optional[Dict[str, str]] = None


class MCPServerResponse(BaseModel):
    """Response for a single MCP server"""
    id: str
    name: str
    uri: str
    transport: str
    auth_type: str
    enabled: bool
    connected: bool
    description: Optional[str]
    tags: List[str]
    tools_count: int
    resources_count: int
    prompts_count: int
    created_at: str
    updated_at: str


# ============== Endpoints ==============

@router.get("/servers")
async def list_servers() -> List[MCPServerResponse]:
    """List all configured MCP servers"""
    servers = []
    
    for config in mcp_manager.configs.values():
        client = mcp_manager.servers.get(config.id)
        # Handle both enum and string types for transport/auth_type
        transport_value = config.transport.value if isinstance(config.transport, MCPTransport) else config.transport
        auth_type_value = config.auth_type.value if isinstance(config.auth_type, MCPAuthType) else config.auth_type
        
        servers.append(MCPServerResponse(
            id=config.id,
            name=config.name,
            uri=config.uri,
            transport=transport_value,
            auth_type=auth_type_value,
            enabled=config.enabled,
            connected=client.connected if client else False,
            description=config.description,
            tags=config.tags or [],
            tools_count=len(client.tools) if client else 0,
            resources_count=len(client.resources) if client else 0,
            prompts_count=len(client.prompts) if client else 0,
            created_at=config.created_at,
            updated_at=config.updated_at,
        ))
    
    return servers


@router.post("/servers")
async def add_server(request: MCPServerCreate):
    """Add a new MCP server"""
    server_id = str(uuid4())
    
    try:
        transport = MCPTransport(request.transport)
    except ValueError:
        raise HTTPException(400, f"Invalid transport: {request.transport}")
    
    try:
        auth_type = MCPAuthType(request.auth_type)
    except ValueError:
        raise HTTPException(400, f"Invalid auth_type: {request.auth_type}")
    
    config = MCPServerConfig(
        id=server_id,
        name=request.name,
        uri=request.uri,
        transport=transport,
        auth_type=auth_type,
        auth_credentials=request.auth_credentials,
        description=request.description,
        tags=request.tags,
        enabled=request.enabled,
    )
    
    success = await mcp_manager.add_server(config)
    client = mcp_manager.servers.get(server_id)
    
    return {
        "id": server_id,
        "name": config.name,
        "uri": config.uri,
        "connected": success,
        "tools_count": len(client.tools) if client else 0,
        "resources_count": len(client.resources) if client else 0,
        "prompts_count": len(client.prompts) if client else 0,
        "message": "Server added and connected" if success else "Server added but connection failed"
    }


@router.put("/servers/{server_id}")
async def update_server(server_id: str, request: MCPServerUpdate):
    """Update an MCP server configuration"""
    config = mcp_manager.configs.get(server_id)
    if not config:
        raise HTTPException(404, "Server not found")
    
    # Update config fields
    if request.name is not None:
        config.name = request.name
    if request.uri is not None:
        config.uri = request.uri
    if request.transport is not None:
        config.transport = MCPTransport(request.transport)
    if request.auth_type is not None:
        config.auth_type = MCPAuthType(request.auth_type)
    if request.auth_credentials is not None:
        config.auth_credentials = request.auth_credentials
    if request.description is not None:
        config.description = request.description
    if request.tags is not None:
        config.tags = request.tags
    if request.enabled is not None:
        config.enabled = request.enabled
    
    config.updated_at = datetime.utcnow().isoformat()
    mcp_manager.save_configs()
    
    # Reconnect if needed
    if config.enabled and server_id not in mcp_manager.servers:
        await mcp_manager.connect_server(server_id)
    elif not config.enabled and server_id in mcp_manager.servers:
        await mcp_manager.disconnect_server(server_id)
    
    return {"status": "updated", "server_id": server_id}


@router.delete("/servers/{server_id}")
async def delete_server(server_id: str):
    """Remove an MCP server"""
    if server_id not in mcp_manager.configs:
        raise HTTPException(404, "Server not found")
    
    await mcp_manager.remove_server(server_id)
    return {"status": "deleted", "server_id": server_id}


@router.post("/servers/{server_id}/connect")
async def connect_server(server_id: str):
    """Connect to an MCP server"""
    if server_id not in mcp_manager.configs:
        raise HTTPException(404, "Server not found")
    
    success = await mcp_manager.connect_server(server_id)
    client = mcp_manager.servers.get(server_id)
    
    return {
        "connected": success,
        "tools_count": len(client.tools) if client else 0,
        "resources_count": len(client.resources) if client else 0,
        "prompts_count": len(client.prompts) if client else 0,
    }


@router.post("/servers/{server_id}/disconnect")
async def disconnect_server(server_id: str):
    """Disconnect from an MCP server"""
    await mcp_manager.disconnect_server(server_id)
    return {"connected": False}


@router.post("/test-connection")
async def test_connection(request: MCPTestConnectionRequest):
    """Test connection to an MCP server without saving"""
    result = await mcp_manager.test_connection(
        uri=request.uri,
        transport=request.transport,
        auth_type=request.auth_type,
        auth_credentials=request.auth_credentials
    )
    return result


# ============== Tools & Resources ==============

@router.get("/tools")
async def list_all_tools():
    """List all tools from all connected MCP servers"""
    tools = mcp_manager.get_all_tools()
    return {
        "total": len(tools),
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "server_id": t.server_id,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]
    }


@router.get("/servers/{server_id}/tools")
async def list_server_tools(server_id: str):
    """List tools from a specific MCP server"""
    client = mcp_manager.servers.get(server_id)
    if not client:
        raise HTTPException(404, "Server not connected")
    
    return {
        "server_id": server_id,
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in client.tools
        ]
    }


@router.post("/tools/call")
async def call_tool(request: MCPToolCallRequest):
    """Call a tool on an MCP server"""
    result = await mcp_manager.call_tool(
        server_id=request.server_id,
        tool_name=request.tool_name,
        arguments=request.arguments
    )
    
    if not result.get("success"):
        raise HTTPException(400, result.get("error", "Tool call failed"))
    
    return result


@router.get("/resources")
async def list_all_resources():
    """List all resources from all connected MCP servers"""
    resources = mcp_manager.get_all_resources()
    return {
        "total": len(resources),
        "resources": [
            {
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mime_type": r.mime_type,
                "server_id": r.server_id,
            }
            for r in resources
        ]
    }


@router.get("/servers/{server_id}/resources")
async def list_server_resources(server_id: str):
    """List resources from a specific MCP server"""
    client = mcp_manager.servers.get(server_id)
    if not client:
        raise HTTPException(404, "Server not connected")
    
    return {
        "server_id": server_id,
        "resources": [
            {
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mime_type": r.mime_type,
            }
            for r in client.resources
        ]
    }


@router.get("/prompts")
async def list_all_prompts():
    """List all prompts from all connected MCP servers"""
    prompts = mcp_manager.get_all_prompts()
    return {
        "total": len(prompts),
        "prompts": [
            {
                "name": p.name,
                "description": p.description,
                "arguments": p.arguments,
                "server_id": p.server_id,
            }
            for p in prompts
        ]
    }


@router.get("/llm-tools")
async def get_llm_compatible_tools():
    """Get all MCP tools in OpenAI-compatible format for LLM function calling"""
    return {
        "tools": mcp_manager.get_tools_for_llm()
    }


# ============== Discovery ==============

@router.post("/servers/{server_id}/refresh")
async def refresh_server(server_id: str):
    """Refresh/rediscover tools and resources from a server"""
    client = mcp_manager.servers.get(server_id)
    if not client:
        raise HTTPException(404, "Server not connected")
    
    await client.discover_all()
    
    return {
        "tools_count": len(client.tools),
        "resources_count": len(client.resources),
        "prompts_count": len(client.prompts),
    }


# ============== Registry ==============

@router.get("/registry")
async def get_server_registry(category: Optional[str] = None, source: Optional[str] = None):
    """
    Get pre-configured MCP servers from the registry.
    Filter by category (Core, Developer Tools, Databases, Security, etc.)
    or source (official, community, docker)
    """
    servers = MCP_SERVER_REGISTRY
    
    if category:
        servers = [s for s in servers if s.get("category", "").lower() == category.lower()]
    if source:
        servers = [s for s in servers if s.get("source", "").lower() == source.lower()]
    
    # Group by category for UI
    categories = {}
    for server in MCP_SERVER_REGISTRY:
        cat = server.get("category", "Other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(server)
    
    return {
        "total": len(servers),
        "servers": servers,
        "categories": list(categories.keys()),
        "sources": ["official", "community", "docker"]
    }


@router.post("/registry/{registry_id}/install")
async def install_from_registry(registry_id: str, auth_values: Optional[Dict[str, str]] = None):
    """Install a server from the registry"""
    # Find server in registry
    registry_server = next((s for s in MCP_SERVER_REGISTRY if s["id"] == registry_id), None)
    if not registry_server:
        raise HTTPException(404, f"Server '{registry_id}' not found in registry")
    
    config = registry_server["config"]
    transport = config.get("transport", "stdio")
    
    # Build URI or command based on transport
    if transport == "http" or transport == "sse":
        uri = config.get("url", "")
        auth_credentials = None
        
        # Apply auth values to headers if provided
        if auth_values and config.get("headers"):
            headers = config.get("headers", {})
            for key, val in headers.items():
                if not val and key in auth_values:
                    headers[key] = auth_values[key]
            auth_credentials = headers
            
    else:
        # For stdio, store command info in URI field with special prefix
        command = config.get("command", "")
        args = config.get("args", [])
        uri = f"stdio://{command}?args={','.join(args)}"
        
        # Handle env vars for auth
        auth_credentials = {}
        if auth_values:
            for key, val in auth_values.items():
                auth_credentials[key] = val
        elif config.get("env"):
            auth_credentials = config.get("env")
    
    server_id = str(uuid4())
    server_config = MCPServerConfig(
        id=server_id,
        name=registry_server["name"],
        uri=uri,
        transport=MCPTransport(transport) if transport in ["http", "sse"] else MCPTransport.HTTP,
        auth_type=MCPAuthType.BEARER if registry_server.get("requires_auth") else MCPAuthType.NONE,
        auth_credentials=auth_credentials if auth_credentials else None,
        description=registry_server["description"],
        tags=registry_server.get("tags", []),
        enabled=True
    )
    
    success = await mcp_manager.add_server(server_config)
    
    return {
        "id": server_id,
        "name": registry_server["name"],
        "installed": True,
        "connected": success,
        "requires_auth": registry_server.get("requires_auth", False),
        "auth_fields": registry_server.get("auth_fields", [])
    }


# ============== Config File Import ==============

class MCPConfigImport(BaseModel):
    """VS Code style mcp.json configuration"""
    servers: Dict[str, Any]
    inputs: Optional[List[Dict[str, Any]]] = None


@router.post("/import/config")
async def import_mcp_config(config: MCPConfigImport):
    """
    Import MCP servers from VS Code style mcp.json configuration.
    Supports stdio, http, and sse transport types.
    
    Example config:
    {
        "servers": {
            "memory": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-memory"]
            },
            "remote-api": {
                "type": "http",
                "url": "https://api.example.com/mcp"
            }
        }
    }
    """
    imported = []
    errors = []
    
    for name, server_config in config.servers.items():
        try:
            server_id = str(uuid4())
            transport = server_config.get("type", "stdio")
            
            # Determine URI based on transport
            if transport in ["http", "sse"]:
                uri = server_config.get("url", "")
                if not uri:
                    errors.append({"name": name, "error": "Missing 'url' for HTTP/SSE server"})
                    continue
            else:
                # STDIO server
                command = server_config.get("command", "")
                args = server_config.get("args", [])
                if not command:
                    errors.append({"name": name, "error": "Missing 'command' for stdio server"})
                    continue
                uri = f"stdio://{command}?args={','.join(str(a) for a in args)}"
            
            # Extract auth from headers or env
            auth_credentials = None
            auth_type = MCPAuthType.NONE
            
            if server_config.get("headers"):
                auth_credentials = server_config["headers"]
                if any("authorization" in k.lower() for k in auth_credentials.keys()):
                    auth_type = MCPAuthType.BEARER
                elif any("api" in k.lower() or "key" in k.lower() for k in auth_credentials.keys()):
                    auth_type = MCPAuthType.API_KEY
            elif server_config.get("env"):
                auth_credentials = server_config["env"]
            
            mcp_config = MCPServerConfig(
                id=server_id,
                name=name,
                uri=uri,
                transport=MCPTransport(transport) if transport in ["http", "sse"] else MCPTransport.HTTP,
                auth_type=auth_type,
                auth_credentials=auth_credentials,
                enabled=True,
                tags=["imported"]
            )
            
            success = await mcp_manager.add_server(mcp_config)
            imported.append({
                "id": server_id,
                "name": name,
                "transport": transport,
                "connected": success
            })
            
        except Exception as e:
            errors.append({"name": name, "error": str(e)})
    
    return {
        "imported_count": len(imported),
        "imported": imported,
        "errors": errors
    }


@router.post("/import/file")
async def import_mcp_config_file(file: UploadFile = File(...)):
    """
    Upload and import an mcp.json configuration file.
    Accepts VS Code style MCP configuration.
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(400, "File must be a JSON file")
    
    try:
        content = await file.read()
        config_data = json.loads(content.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(400, f"Error reading file: {str(e)}")
    
    # Validate structure
    if "servers" not in config_data:
        raise HTTPException(400, "Config file must have a 'servers' object")
    
    config = MCPConfigImport(**config_data)
    return await import_mcp_config(config)


# ============== LLM Config Import ==============

class LLMConfigImport(BaseModel):
    """LLM provider configuration"""
    provider: str
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


@router.post("/import/llm-config")
async def import_llm_config(config: LLMConfigImport):
    """
    Import LLM configuration.
    This updates the current LLM settings.
    """
    from app.api.settings import update_provider
    
    provider_config = {
        "provider": config.provider,
        "model": config.model,
    }
    
    if config.api_key:
        provider_config["api_key"] = config.api_key
    if config.base_url:
        provider_config["base_url"] = config.base_url
    if config.extra:
        provider_config.update(config.extra)
    
    # Use the existing settings update endpoint
    from pydantic import BaseModel as PydanticBaseModel
    
    class ProviderConfigRequest(PydanticBaseModel):
        provider: str
        api_key: Optional[str] = None
        model: Optional[str] = None
        base_url: Optional[str] = None
    
    request = ProviderConfigRequest(**provider_config)
    result = await update_provider(request)
    
    return {
        "success": True,
        "provider": config.provider,
        "model": config.model,
        "message": "LLM configuration imported successfully"
    }


@router.post("/import/llm-file")
async def import_llm_config_file(file: UploadFile = File(...)):
    """
    Upload and import an LLM configuration file.
    
    Expected format:
    {
        "provider": "openai",
        "model": "gpt-4o",
        "api_key": "sk-...",
        "base_url": "https://api.openai.com/v1"
    }
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(400, "File must be a JSON file")
    
    try:
        content = await file.read()
        config_data = json.loads(content.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(400, f"Error reading file: {str(e)}")
    
    config = LLMConfigImport(**config_data)
    return await import_llm_config(config)


# ============== Export Configuration ==============

@router.get("/export/config")
async def export_mcp_config():
    """
    Export current MCP configuration as VS Code compatible mcp.json format.
    """
    servers = {}
    
    for config in mcp_manager.configs.values():
        server_config = {}
        
        if config.transport == MCPTransport.HTTP or config.transport == MCPTransport.SSE:
            server_config["type"] = config.transport.value
            server_config["url"] = config.uri
            if config.auth_credentials:
                server_config["headers"] = config.auth_credentials
        else:
            # Parse stdio URI back to command/args
            if config.uri.startswith("stdio://"):
                parts = config.uri[8:].split("?args=")
                server_config["command"] = parts[0]
                if len(parts) > 1:
                    server_config["args"] = parts[1].split(",")
            else:
                server_config["type"] = "http"
                server_config["url"] = config.uri
        
        servers[config.name] = server_config
    
    return {
        "servers": servers,
        "inputs": []  # User should add input variables manually for security
    }

