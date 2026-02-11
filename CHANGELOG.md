# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-21

### Added

- **Enhanced Threat Model Experience** - Threats now include detailed context for better understanding
  - "Where this happens" - Clickable component/flow chips linking threats to DFD elements
  - Attack Scenario - Preconditions, step-by-step attack steps, and impact narrative
  - Structured Mitigations - PREVENT/DETECT/RESPOND types with status, owner, and verification
  - Transparent Risk Scoring - DREAD model with human-readable explanations
  
- **Flow Map Deep Linking** - Click component/flow chips to navigate directly to DFD with highlighting
  - `?focusComponent=id` and `?focusFlow=id` URL parameters
  - Visual highlighting of focused elements in Mermaid diagrams
  - Focus banner with clear-focus button
  
- **Backend Enhancements**
  - New `ThreatEnhanced` Pydantic model with all new fields
  - `StructuredMitigation` model with type, status, owner, verification
  - Automatic mitigation type inference from text (PREVENT/DETECT/RESPOND)
  - Backward-compatible migration for existing threats
  - Enhanced DREAD engine with `scoring_explanation` and `scoring_model`
  - Neo4j graph support for threat-component-flow relationships
  
- **Frontend Enhancements**
  - Expanded threat panel with new sections (location, scenario, mitigations)
  - Updated ThreatEditor with structured mitigation management
  - Component/flow selection in threat editor
  - Attack scenario builder (preconditions, steps, impact)
  - Risk explanation tooltip in DREAD display

### Changed

- Threat API endpoints now return enhanced threat format with new fields
- Flow Map endpoint supports `focusComponent` and `focusFlow` query params
- ThreatEditor supports structured mitigations alongside legacy text mitigations

### Backward Compatibility

- Existing threats are automatically migrated on load with sensible defaults
- Legacy `mitigations` (string array) preserved alongside new `structured_mitigations`
- All new fields are optional with defaults to ensure existing data renders correctly

## [1.0.0] - 2026-01-20

### Added

- Initial release of PadmaVue.ai
- AI-powered threat modeling with STRIDE and PASTA methodologies
- MAESTRO framework support for agentic AI threat modeling
- DREAD scoring for risk quantification
- Data Flow Diagram (DFD) generation with Mermaid
- Compliance mapping to NIST 800-53 and OWASP ASVS
- DevSecOps rule generation (Checkov, tfsec, Semgrep)
- Multi-provider LLM support (OpenAI, Anthropic, Ollama, OpenRouter, etc.)
- Web search integration for grounded responses (SearXNG, Tavily, etc.)
- MCP (Model Context Protocol) server integration
- Docker support with lite and full deployment modes
- Comprehensive REST API with FastAPI
- Modern React/Next.js frontend with dark mode support
- Security hardening with rate limiting, input validation, and audit logging

### Security

- Security headers middleware with CSP, X-Frame-Options, etc.
- Path traversal protection in file uploads
- Sensitive data masking in logs
- Non-root Docker containers
- Input validation on all API endpoints
