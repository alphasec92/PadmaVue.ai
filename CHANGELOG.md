# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
