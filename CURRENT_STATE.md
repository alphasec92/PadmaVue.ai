# CURRENT_STATE

Last updated: 2026-01-18 (Rev 4)

This document summarizes what the codebase does today and the current runtime shape of the system. Update it whenever you introduce behavior changes, new components, or material architecture changes.

## What This System Is
- **PadmaVue.ai** is a local-first, AI-powered security review platform.
- It supports **document ingestion + automated threat modeling** (STRIDE/PASTA + optional MAESTRO overlay), **DFD generation**, **OWASP compliance mappings** (including AI/LLM and Agentic AI Top 10), and **DevSecOps rule suggestions**.
- It includes **two interaction modes**:
  - **File-based upload + analysis**
  - **Conversational Security Architect (chat + questionnaire)**

## MAESTRO (Agentic AI) Integration (2026-01-16)
- **MAESTRO** (Multi-Agent Environment Security Threat Risk & Opportunity) can be enabled as an **overlay** alongside STRIDE or PASTA.
- **AI-Driven Applicability**: The system automatically detects AI/agent components from:
  - Project metadata and description
  - Uploaded documents and code
  - User responses in elicitation/architect flows
  - Configuration (MCP servers, LLM providers, web search)
- **No-Hallucination Guarantee**: MAESTRO threats are ONLY generated when:
  - AI/agent signals are detected with sufficient confidence (default threshold: 60%)
  - OR the user explicitly forces MAESTRO analysis
- **Evidence-Based**: All applicability decisions include:
  - Confidence score (0-100%)
  - Detection reasons
  - Evidence snippets from source documents
- **MAESTRO Categories**:
  - AGENT01: Autonomous Action Abuse
  - AGENT02: Multi-Agent Coordination Attacks
  - AGENT03: Tool/MCP Exploitation
  - AGENT04: Memory/Context Manipulation
  - AGENT05: Goal/Objective Hijacking
  - AGENT06: LLM Decision Trust Exploitation

## Key User Workflows
1. **Upload → Analyze → Review → DFD**: Upload documents, run threat analysis, review findings, view/edit DFD
2. **AI Architect (Form) → Review → DFD**: Answer guided questions, get threat model generated
3. **AI Architect (Chat) → Review**: Conversational threat discovery with AI

## Major Components

### Backend (FastAPI)
- **Entry point**: `backend/app/main.py`
- **Core responsibilities**:
  - API endpoints for ingestion, analysis, DFD, reporting, settings, threats, architect flows, exports, and MCP server metadata.
  - Security middleware: request logging, request ID, security headers, and rate limiting.
  - Service initialization for **Neo4j**, **Qdrant**, and **MCP** connections (best-effort; degraded mode if unavailable).

#### Core API Flows
- **Ingestion** (`/api/ingest`):
  - Validates filenames/extensions and size.
  - Stores files under `backend/uploads/<project_id>/`.
  - Creates a **Project** record in file-based storage.
- **Analysis** (`/api/analyze`):
  - Loads project data from storage.
  - Runs the **SecurityOrchestrator** (LangGraph) pipeline:
    1. Elicitation Agent
    2. Threat Agent (STRIDE/PASTA + DREAD)
    3. Compliance Agent
    4. Diagram Agent (Mermaid DFD)
    5. DevSecOps Agent
    6. Guardrail Agent
  - Persists results (analysis + threats + report).
- **Report generation** (`/api/report`):
  - Creates report artifacts in JSON or Markdown and stores them in `backend/data/exports/`.
- **Security Architect**:
  - **Chat-based** flow: `/api/architect-chat/*` (sessioned, stored in `backend/data/architect_sessions/`).
  - **Questionnaire** flow: `/api/architect/analyze-form` (structured form → threats + DFD + compliance summary).
- **Settings** (`/api/settings`):
  - Runtime (in-memory) provider configuration for LLMs.
  - Provider testing and local Ollama model listing.

#### Storage (Persistent)
- **File-based JSON repository** in `backend/data/`:
  - `projects/` - Project metadata (name, description, files, timestamps)
  - `analyses/` - Analysis results (threats, DFD, compliance, status)
  - `reports/` - Generated report artifacts
  - `threats/` - Individual threat records linked to analyses
  - `exports/` - Exported report files (JSON, MD)
  - `architect_sessions/` - AI Architect chat sessions
  - `chat_sessions/` - General chat sessions
- **Uploads**: `backend/uploads/`.
- **Logs**: `backend/logs/`.
- **Data persists across restarts** - All analyses, projects, and threats remain available.

#### LLM Providers
- Supported providers (runtime-configured + env-based):
  - `mock`, `openai`, `anthropic`, `openrouter`, `gemini`, `vertex`, `bedrock`, `ollama`, `lmstudio`.
- Provider configuration is applied **in memory** (not persisted to `.env`).

#### Web Search (Grounded Responses)
- Optional web-grounded responses via providers like **SearXNG** (recommended) or paid search APIs (Tavily, Serper, Brave, Bing).
- **Setup SearXNG**: `docker compose -f infra/docker/compose/docker-compose.search.yml up -d`
- Configure `SEARCH_PROVIDER=searxng` in `backend/.env` and restart.
- Configured through `SEARCH_PROVIDER` and related env vars in `backend/app/config.py`.
- **Endpoints**:
  - `GET /api/architect-chat/web-search/status` - Check provider availability
  - `GET /api/architect-chat/web-search/providers` - List available providers
  - `GET /api/architect-chat/web-search/test` - Test search connectivity with sample query
- **Settings**: Frontend settings modal includes:
  - "Always Enable for Grounded Responses" toggle (persisted to localStorage)
  - "Test Web Search Connection" button

#### MCP Integration
- MCP server definitions in `backend/app/api/mcp.py`.
- MCP connections are initialized at startup (`mcp_manager.connect_all()`).

### Frontend (Next.js)
- **Entry point**: `frontend/app/`
- **Major routes**:
  - `/` → Landing page with feature highlights and settings modal.
  - `/upload` → File upload + methodology selection (STRIDE/PASTA + optional MAESTRO overlay).
  - `/review` → Threat review, filtering, editing, export, and diagram editing. Includes "View DFD" navigation.
  - `/dfd` → Mermaid diagram renderer + export + zoom controls. **Now tied to analysis context** with methodology badge, threat count, and "View Threats" navigation.
  - `/ai-architect` → Conversational chat-based architect.
  - `/architect` → Guided questionnaire-based architect.
- **Settings modal** configures LLM providers and MCP.
- **Diagram Editor** (modal): Full-featured editor for zones, trust boundaries, components, and data flows. Preview updates in real-time.

#### Frontend/Backend Interaction
- Uses `frontend/lib/api.ts` for API requests (base `http://localhost:8000`).
- `/review` loads recent analyses, threats, and diagram metadata via backend endpoints.
- `/dfd` pulls DFD from analysis and renders via Mermaid. **Auto-loads most recent analysis if none specified.**

#### Navigation Improvements (2026-01-15)
- **Review → DFD**: "View DFD" button navigates to `/dfd?analysis_id=...`.
- **DFD → Review**: "View Threats" button navigates to `/review?analysis_id=...`.
- Both pages display analysis context (methodology, threat count, project name).

## Runtime Defaults
- **Frontend**: `http://localhost:3000`
- **Backend**: `http://localhost:8000`
- **Neo4j** (full mode): `http://localhost:7474`
- **Qdrant** (full mode): `http://localhost:6333`

## Deployment & Packaging
- **Dockerfiles** in `backend/` and `frontend/`.
- Compose files:
  - `compose.lite.yml` (frontend + backend)
  - `compose.full.yml` (+ Neo4j + Qdrant)
  - `docker-compose.hub.yml` (prebuilt images)
- CI/CD:
  - `.github/workflows/deploy.yml` (AWS ECS)
  - `.github/workflows/docker-publish.yml` (GHCR build/publish)

## Known Constraints / Gaps
- **DFD API (`/api/dfd`) still uses legacy in-memory stores** (`ingestion_store`, `analysis_store`) rather than the file-based repository.
  - As a result, direct DFD API requests may not find projects created via `/api/ingest`.
  - The DFD output shown in the UI mostly comes from `analysis.dfd_mermaid` produced by the orchestrator.
- **Runtime LLM configuration is in-memory** and resets on backend restart.
- **Search provider config** requires explicit API keys or a local SearXNG instance.
- **Diagram Editor** visual builder functionality needs further testing for complex diagrams.

## Data Models (Key Fields)

### ProjectData (`backend/app/storage/repository.py`)
| Field | Type | Description |
|-------|------|-------------|
| `id` | str | UUID |
| `name` | str | Project name |
| `description` | str | Optional description |
| `status` | str | created, ingested, analyzing, completed, failed |
| `files` | List[Dict] | Uploaded file metadata |
| `metadata` | Dict | Additional metadata |
| `source` | Optional[str] | Where project was created from (upload, architect) |
| `architecture_types` | List[str] | Architecture types (web, mobile, api, etc.) |
| `methodology` | Optional[str] | STRIDE or PASTA |
| `created_at` | str | ISO timestamp |
| `updated_at` | str | ISO timestamp |

### AnalysisData (`backend/app/storage/repository.py`)
| Field | Type | Description |
|-------|------|-------------|
| `id` | str | UUID |
| `project_id` | str | Parent project UUID |
| `methodology` | str | STRIDE or PASTA |
| `status` | str | pending, in_progress, completed, failed |
| `threats` | List[Dict] | Generated threats |
| `compliance_summary` | Dict | NIST/OWASP mappings |
| `dfd_mermaid` | Optional[str] | Mermaid diagram code |
| `devsecops_rules` | Dict | Generated rules |
| `created_at` | str | ISO timestamp |
| `completed_at` | Optional[str] | ISO timestamp |

## Recent Fixes (2026-01-15)

### Data Model Fixes
- **Fixed**: `ProjectData` dataclass was missing fields (`source`, `architecture_types`, `methodology`) that were saved by the Architect Form workflow, causing 500 errors when listing projects.
- **Fixed**: `ReportRepository.create()` parameter mismatch (`format` → `fmt`) that caused 500 errors on analysis completion.

### Frontend Fixes
- **Fixed**: DFD page initial render - diagram now loads correctly without requiring manual refresh.
- **Improved**: DFD page now shows analysis context (project name, methodology badge, threat count, analysis status).
- **Added**: Bidirectional navigation between Review and DFD pages via "View DFD" and "View Threats" buttons.

### Error Handling Improvements
- **Added**: Custom exceptions module (`backend/app/core/exceptions.py`) for user-friendly error messages with categorization:
  - `ErrorCategory` enum: file_error, llm_error, validation_error, not_found, rate_limit, configuration, database, internal
  - `AnalysisError` base class with `to_response()` and `to_log_context()` methods
  - Specialized exceptions: `LLMError`, `DatabaseError`, `NotFoundError`, `FileError`, `ValidationError`, `RateLimitError`, `ConfigurationError`
  - `classify_error()` helper to convert unknown exceptions into categorized errors

### Analysis History Features
- **Added**: Analysis History component (`frontend/components/analysis-history.tsx`) with:
  - List of all past analyses with project names, methodologies, timestamps, and threat counts
  - Search and filter by methodology
  - Relative time formatting ("Just now", "3h ago", "5d ago")
  - Click to load analysis in Review page
- **Added**: Analysis Selector dropdown in Review page header for switching between analyses
- **Improved**: Review page now shows:
  - Project name in header
  - Analysis timestamp (created + completed)
  - Analysis ID (truncated)
  - History view when no analysis is selected
- **Enhanced**: `/api/analyze/list` now includes project names and descriptions for enriched frontend display

### OWASP Framework Integration (2026-01-15 Rev 3)
- **Added**: Comprehensive OWASP mapper module (`backend/app/engines/owasp_mapper.py`):
  - **OWASP Top 10 Web (2021)**: A01-A10 covering web application security risks
  - **OWASP API Security Top 10 (2023)**: API1-API10 for API-specific threats
  - **OWASP LLM AI Top 10 (2025)**: LLM01-LLM10 for AI/ML security (prompt injection, data poisoning, etc.)
  - **Agentic AI Security**: AGENT01-AGENT05 for autonomous AI agent threats
- **Enhanced**: Threat Agent now automatically detects AI/ML and Agent components:
  - `_detect_ai_components()`: Identifies LLM, ML, embedding, neural network usage
  - `_detect_agent_components()`: Identifies agentic AI, tool calling, MCP, orchestration
  - `_detect_api_components()`: Identifies API exposure (REST, GraphQL, webhooks)
- **Enhanced**: Threat generation prompts include OWASP mappings for each threat
- **Enhanced**: Default STRIDE threats include OWASP ID mappings
- **Added**: AI-specific threat generation when AI/Agent components detected:
  - Prompt Injection (LLM01:2025)
  - Sensitive Data Leakage (LLM02:2025)
  - Hallucination/Misinformation (LLM09:2025)
  - Excessive Agent Autonomy (LLM06:2025)
  - Tool/API Abuse (AGENT02)
  - Agent Memory Manipulation (AGENT03)
- **Added**: AI-specific mitigations with implementation steps
- **Added**: OWASP compliance report generation

### Frontend OWASP Display
- **Added**: OWASP badge component (`frontend/components/owasp-badge.tsx`):
  - `OWASPBadge`: Expandable OWASP mappings with external links
  - `OWASPInlineBadges`: Compact badges for threat cards
  - `AIThreatSummary`: Summary component for AI-specific threats
  - Color-coded by framework (Web=blue, API=purple, LLM/AI=amber, Agentic=red)
- **Updated**: Review page displays OWASP mappings for each threat
- **Updated**: Threat cards show inline OWASP badge count and AI indicator
- **Updated**: Threat type in API includes `owasp_mappings` field

## Recent Fixes (2026-01-18)

### LLM Configuration Error UX
- **Added**: User-friendly error handling when LLM provider is not configured
- **Added**: `isLLMConfigError()` helper function to detect LLM configuration errors
- **Added**: "Configure in Settings" button that opens Settings modal directly from error messages
- **Updated**: Error styling uses amber color (warning) instead of red for config issues
- **Files changed**: 
  - `frontend/app/ai-architect/page.tsx`
  - `frontend/app/upload/page.tsx`
  - `frontend/app/architect/page.tsx`

### Start Script Enhancements
- **Added**: Model selection by number in setup scripts
- **Updated**: `start.sh` and `start.ps1` now display numbered model list:
  ```
  Available models:
    1) llama3.2:latest       ...
    2) deepseek-r1:latest    ...
  Select model (number or name, default: llama3.2):
  ```
- Users can enter number (e.g., `1`) or model name (e.g., `llama3.2`)

### Web Search Improvements
- **Added**: "Always Enable for Grounded Responses" toggle in Settings
- **Added**: `defaultEnabled` state in `useWebSearch` hook persisted to localStorage
- **Added**: `testConnection()` function to verify web search provider connectivity
- **Added**: `/api/architect-chat/web-search/test` endpoint for testing search providers
- **Updated**: Settings modal shows test button and setup instructions for SearXNG

### AI/ML Threat Model Builder Expansion
- **Added**: New questions for AI agents, MCP, and tool-calling capabilities
- **Added**: `ai_agent_capabilities` question covering:
  - Tool/Function Calling
  - MCP (Model Context Protocol)
  - Direct API Access
  - Code Execution
  - File System Access
  - Database Access
  - Autonomous Decisions
- **Added**: `ai_mcp_servers` textarea for listing MCP servers/tools
- **Updated**: `ai_type` question includes AI Agent, Multi-Agent, RAG options
- **Updated**: `ai_security_concerns` includes OWASP LLM Top 10 (2025) and Agentic AI categories
- **Added**: `ai_guardrails` question for safety measures

### Rate Limiting Fixes
- **Fixed**: Frontend polling endpoints (`/status`, `/providers`) now exempt from rate limiting
- **Increased**: Default rate limit from 300 to 600 requests per minute for development

## How to Keep This Current
- Update this file whenever:
  - API contracts or behavior changes.
  - New services, storage formats, or providers are added.
  - Frontend routes or flows change.
  - Deployment or runtime assumptions change.
