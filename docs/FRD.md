# Functional Requirements Document (FRD)
## PadmaVue.ai

**Document Version:** 1.1
**Date:** January 15, 2026
**Status:** Active

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview](#2-system-overview)
3. [User Roles and Personas](#3-user-roles-and-personas)
4. [Functional Requirements](#4-functional-requirements)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [System Architecture](#6-system-architecture)
7. [Data Requirements](#7-data-requirements)
8. [Interface Requirements](#8-interface-requirements)
9. [Security Requirements](#9-security-requirements)
10. [Error Handling](#10-error-handling)
11. [Appendices](#appendices)

---

## 1. Introduction

### 1.1 Purpose

This Functional Requirements Document (FRD) defines the detailed functional and technical specifications for PadmaVue.ai, an AI-powered security review platform. It serves as the authoritative reference for development, testing, and validation activities.

### 1.2 Scope

This document covers all functional capabilities of the PadmaVue.ai platform, including:
- Document ingestion and processing
- AI-powered threat modeling (STRIDE/PASTA + optional MAESTRO overlay for Agentic AI)
- Compliance mapping (NIST 800-53, OWASP ASVS, OWASP LLM Top 10, OWASP Agentic AI)
- DevSecOps rule generation
- Data flow diagram generation
- Report export functionality
- Conversational security analysis

### 1.3 Definitions and Acronyms

| Term | Definition |
|------|------------|
| API | Application Programming Interface |
| DFD | Data Flow Diagram |
| DREAD | Damage, Reproducibility, Exploitability, Affected Users, Discoverability |
| FRD | Functional Requirements Document |
| LLM | Large Language Model |
| MAESTRO | Multi-Agent Environment Security Threat Risk & Opportunity |
| MCP | Model Context Protocol |
| PASTA | Process for Attack Simulation and Threat Analysis |
| RAG | Retrieval-Augmented Generation |
| STRIDE | Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege |

### 1.4 References

- NIST SP 800-53 Rev. 5: Security and Privacy Controls
- OWASP Application Security Verification Standard (ASVS) 4.0
- OWASP LLM AI Top 10
- OWASP Agentic AI Security
- Microsoft STRIDE Threat Model
- PASTA Risk-Centric Threat Modeling Methodology
- MAESTRO Framework for Agentic AI Security

---

## 2. System Overview

### 2.1 System Description

PadmaVue.ai is a web-based platform that automates security threat modeling through AI-powered analysis. The system accepts architecture documentation or conversational input, processes it through specialized AI agents, and produces comprehensive security artifacts including threat findings, compliance mappings, and DevSecOps rules.

### 2.2 System Context Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              USERS                                      │
│  [Security Architects] [Security Engineers] [Developers] [Compliance]  │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           PADMAVUE.AI                                  │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │   Frontend   │◄──►│   Backend    │◄──►│   AI Processing Layer    │  │
│  │  (Next.js)   │    │  (FastAPI)   │    │  (LangGraph Agents)      │  │
│  └──────────────┘    └──────────────┘    └──────────────────────────┘  │
│                             │                        │                  │
│                             ▼                        ▼                  │
│                      ┌─────────────────────────────────────┐           │
│                      │         Data Storage Layer          │           │
│                      │  [JSON Files] [Neo4j] [Qdrant]      │           │
│                      └─────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL SERVICES                                │
│  [OpenAI] [Anthropic] [Google] [AWS Bedrock] [Ollama] [Web Search]     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Key System Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| Frontend | Next.js 14, React 18, TypeScript | User interface |
| Backend API | FastAPI, Python 3.11+ | REST API services |
| Agent Orchestration | LangGraph, LangChain | AI workflow management |
| Graph Database | Neo4j 5.26+ | Threat relationship storage (optional) |
| Vector Database | Qdrant 1.12+ | Semantic document search (optional) |
| File Storage | Local filesystem | Document and analysis storage |

---

## 3. User Roles and Personas

### 3.1 Primary Users

#### 3.1.1 Security Architect
- **Goals**: Conduct comprehensive threat modeling efficiently
- **Tasks**: Upload architecture docs, review threats, validate compliance mappings
- **Technical Level**: High
- **Usage Frequency**: Daily/Weekly

#### 3.1.2 Security Engineer
- **Goals**: Generate DevSecOps rules for CI/CD integration
- **Tasks**: Export rules, configure scanning tools, review DFDs
- **Technical Level**: High
- **Usage Frequency**: Weekly

#### 3.1.3 Application Developer
- **Goals**: Understand security implications of design decisions
- **Tasks**: Review threat findings, implement mitigations
- **Technical Level**: Medium
- **Usage Frequency**: As needed

### 3.2 Secondary Users

#### 3.2.1 Compliance Officer
- **Goals**: Validate compliance control mappings
- **Tasks**: Review compliance reports, export documentation
- **Technical Level**: Low-Medium
- **Usage Frequency**: Monthly/Quarterly

---

## 4. Functional Requirements

### 4.1 Document Ingestion Module

#### FR-4.1.1 File Upload

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1.1.1 | System shall accept file uploads via drag-and-drop interface | High |
| FR-4.1.1.2 | System shall accept file uploads via file browser dialog | High |
| FR-4.1.1.3 | System shall support batch upload of multiple files | Medium |
| FR-4.1.1.4 | System shall display upload progress for each file | Medium |
| FR-4.1.1.5 | System shall validate file types before processing | Critical |

#### FR-4.1.2 Supported File Types

| ID | File Type | Extensions | Max Size |
|----|-----------|------------|----------|
| FR-4.1.2.1 | PDF Documents | .pdf | 10 MB |
| FR-4.1.2.2 | Markdown | .md | 10 MB |
| FR-4.1.2.3 | Plain Text | .txt | 10 MB |
| FR-4.1.2.4 | JSON | .json | 10 MB |
| FR-4.1.2.5 | YAML | .yaml, .yml | 10 MB |
| FR-4.1.2.6 | XML | .xml | 10 MB |
| FR-4.1.2.7 | Python Source | .py | 10 MB |
| FR-4.1.2.8 | JavaScript | .js | 10 MB |
| FR-4.1.2.9 | TypeScript | .ts | 10 MB |
| FR-4.1.2.10 | Terraform | .tf | 10 MB |
| FR-4.1.2.11 | Word Documents | .docx | 10 MB |

#### FR-4.1.3 Document Processing

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1.3.1 | System shall extract text content from uploaded documents | Critical |
| FR-4.1.3.2 | System shall parse structured data from JSON/YAML files | High |
| FR-4.1.3.3 | System shall compute SHA256 hash for each uploaded file | High |
| FR-4.1.3.4 | System shall sanitize filenames for secure storage | Critical |
| FR-4.1.3.5 | System shall reject files exceeding size limits with clear error | High |

#### FR-4.1.4 Project Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1.4.1 | System shall create a project container for each upload session | High |
| FR-4.1.4.2 | System shall assign unique UUID to each project | Critical |
| FR-4.1.4.3 | System shall track project status (ingested, analyzing, completed, failed) | High |
| FR-4.1.4.4 | System shall allow retrieval of project by ID | High |
| FR-4.1.4.5 | System shall allow deletion of projects and associated data | Medium |
| FR-4.1.4.6 | System shall list all projects with pagination | Medium |

---

### 4.2 Threat Modeling Module

#### FR-4.2.1 Methodology Selection

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.2.1.1 | System shall support STRIDE threat modeling methodology | Critical |
| FR-4.2.1.2 | System shall support PASTA threat modeling methodology | Critical |
| FR-4.2.1.3 | System shall support MAESTRO threat modeling methodology for Agentic AI | Critical |
| FR-4.2.1.4 | User shall select methodology before initiating analysis | High |
| FR-4.2.1.5 | System shall provide methodology description to assist selection | Medium |
| FR-4.2.1.6 | System shall auto-detect AI/agent components for MAESTRO applicability | High |

#### FR-4.2.2 STRIDE Analysis

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.2.2.1 | System shall identify **Spoofing** threats (identity impersonation) | Critical |
| FR-4.2.2.2 | System shall identify **Tampering** threats (data modification) | Critical |
| FR-4.2.2.3 | System shall identify **Repudiation** threats (deniability of actions) | Critical |
| FR-4.2.2.4 | System shall identify **Information Disclosure** threats (data leakage) | Critical |
| FR-4.2.2.5 | System shall identify **Denial of Service** threats (availability attacks) | Critical |
| FR-4.2.2.6 | System shall identify **Elevation of Privilege** threats (unauthorized access) | Critical |
| FR-4.2.2.7 | System shall map each threat to affected security property (CIA) | High |

#### FR-4.2.3 PASTA Analysis

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.2.3.1 | System shall execute Stage 1: Define Business Objectives | Critical |
| FR-4.2.3.2 | System shall execute Stage 2: Define Technical Scope | Critical |
| FR-4.2.3.3 | System shall execute Stage 3: Decompose Application | Critical |
| FR-4.2.3.4 | System shall execute Stage 4: Analyze Threats | Critical |
| FR-4.2.3.5 | System shall execute Stage 5: Identify Vulnerabilities | Critical |
| FR-4.2.3.6 | System shall execute Stage 6: Enumerate Attacks | Critical |
| FR-4.2.3.7 | System shall execute Stage 7: Perform Risk/Impact Analysis | Critical |

#### FR-4.2.3.5 MAESTRO Analysis (Agentic AI)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.2.3.5.1 | System shall identify **AGENT01** Autonomous Action Abuse threats | Critical |
| FR-4.2.3.5.2 | System shall identify **AGENT02** Multi-Agent Coordination Attack threats | Critical |
| FR-4.2.3.5.3 | System shall identify **AGENT03** Tool/MCP Exploitation threats | Critical |
| FR-4.2.3.5.4 | System shall identify **AGENT04** Memory/Context Manipulation threats | Critical |
| FR-4.2.3.5.5 | System shall identify **AGENT05** Goal/Objective Hijacking threats | Critical |
| FR-4.2.3.5.6 | System shall identify **AGENT06** LLM Decision Trust Exploitation threats | Critical |
| FR-4.2.3.5.7 | System shall detect AI/agent components from documents, code, and config | High |
| FR-4.2.3.5.8 | System shall map MAESTRO threats to OWASP LLM Top 10 | High |

> Reference: [CSA MAESTRO Framework](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)

#### FR-4.2.4 Threat Output

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.2.4.1 | Each threat shall have a unique identifier | Critical |
| FR-4.2.4.2 | Each threat shall have a descriptive title | Critical |
| FR-4.2.4.3 | Each threat shall have a detailed description | Critical |
| FR-4.2.4.4 | Each threat shall identify the affected component | High |
| FR-4.2.4.5 | Each threat shall have a severity level (Critical/High/Medium/Low) | Critical |
| FR-4.2.4.6 | Each threat shall include recommended mitigations | Critical |
| FR-4.2.4.7 | Each threat shall include attack vector description | High |

---

### 4.3 Risk Scoring Module (DREAD)

#### FR-4.3.1 DREAD Score Calculation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.3.1.1 | System shall calculate **Damage** score (1-10 scale) | High |
| FR-4.3.1.2 | System shall calculate **Reproducibility** score (1-10 scale) | High |
| FR-4.3.1.3 | System shall calculate **Exploitability** score (1-10 scale) | High |
| FR-4.3.1.4 | System shall calculate **Affected Users** score (1-10 scale) | High |
| FR-4.3.1.5 | System shall calculate **Discoverability** score (1-10 scale) | High |
| FR-4.3.1.6 | System shall compute overall DREAD score as average of components | High |
| FR-4.3.1.7 | System shall assign priority based on DREAD score thresholds | High |

#### FR-4.3.2 DREAD Score Thresholds

| Score Range | Priority | Action Required |
|-------------|----------|-----------------|
| 8.0 - 10.0 | Critical | Immediate remediation |
| 6.0 - 7.9 | High | Address in current sprint |
| 4.0 - 5.9 | Medium | Plan for upcoming release |
| 1.0 - 3.9 | Low | Address as resources permit |

---

### 4.4 Compliance Mapping Module

#### FR-4.4.1 NIST 800-53 Mapping

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.4.1.1 | System shall map threats to NIST 800-53 control families | Critical |
| FR-4.4.1.2 | System shall identify primary controls for each threat | Critical |
| FR-4.4.1.3 | System shall identify secondary/supporting controls | High |
| FR-4.4.1.4 | System shall provide control descriptions | Medium |
| FR-4.4.1.5 | System shall generate compliance coverage summary | High |

#### FR-4.4.2 NIST Control Families Supported

| Family Code | Family Name |
|-------------|-------------|
| AC | Access Control |
| AU | Audit and Accountability |
| AT | Awareness and Training |
| CM | Configuration Management |
| CP | Contingency Planning |
| IA | Identification and Authentication |
| IR | Incident Response |
| MA | Maintenance |
| MP | Media Protection |
| PE | Physical and Environmental Protection |
| PL | Planning |
| PM | Program Management |
| PS | Personnel Security |
| PT | Personally Identifiable Information Processing |
| RA | Risk Assessment |
| SA | System and Services Acquisition |
| SC | System and Communications Protection |
| SI | System and Information Integrity |
| SR | Supply Chain Risk Management |

#### FR-4.4.3 OWASP ASVS Mapping

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.4.3.1 | System shall map threats to OWASP ASVS verification requirements | Critical |
| FR-4.4.3.2 | System shall assign ASVS level (L1/L2/L3) for each requirement | High |
| FR-4.4.3.3 | System shall categorize by ASVS chapter | High |

#### FR-4.4.4 OWASP ASVS Chapters Supported

| Chapter | Description |
|---------|-------------|
| V1 | Architecture, Design and Threat Modeling |
| V2 | Authentication |
| V3 | Session Management |
| V4 | Access Control |
| V5 | Validation, Sanitization and Encoding |
| V6 | Stored Cryptography |
| V7 | Error Handling and Logging |
| V8 | Data Protection |
| V9 | Communication |
| V10 | Malicious Code |
| V11 | Business Logic |
| V12 | Files and Resources |
| V13 | API and Web Service |
| V14 | Configuration |

---

### 4.5 Data Flow Diagram Module

#### FR-4.5.1 DFD Generation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.5.1.1 | System shall generate data flow diagrams in Mermaid format | High |
| FR-4.5.1.2 | DFD shall identify external entities (actors) | High |
| FR-4.5.1.3 | DFD shall identify processes (system components) | High |
| FR-4.5.1.4 | DFD shall identify data stores | High |
| FR-4.5.1.5 | DFD shall show data flows between elements | High |
| FR-4.5.1.6 | DFD shall indicate trust boundaries | Medium |
| FR-4.5.1.7 | DFD shall annotate threat locations on diagram | High |

#### FR-4.5.2 DFD Visualization

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.5.2.1 | System shall render Mermaid diagrams in browser | High |
| FR-4.5.2.2 | User shall be able to zoom and pan diagram | Medium |
| FR-4.5.2.3 | User shall be able to edit diagram source code | Medium |
| FR-4.5.2.4 | System shall validate Mermaid syntax before rendering | High |
| FR-4.5.2.5 | User shall be able to export diagram as image | Medium |

---

### 4.6 DevSecOps Rules Module

#### FR-4.6.1 Rule Generation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.6.1.1 | System shall generate Checkov rules for IaC scanning | High |
| FR-4.6.1.2 | System shall generate tfsec rules for Terraform scanning | High |
| FR-4.6.1.3 | System shall generate Semgrep patterns for code analysis | High |
| FR-4.6.1.4 | Rules shall be linked to corresponding threats | High |
| FR-4.6.1.5 | Rules shall include severity level | High |
| FR-4.6.1.6 | Rules shall include remediation guidance | Medium |

#### FR-4.6.2 Rule Output Format

| Tool | Format | Output Location |
|------|--------|-----------------|
| Checkov | Python/YAML | `devsecops_rules.checkov` |
| tfsec | YAML | `devsecops_rules.tfsec` |
| Semgrep | YAML | `devsecops_rules.semgrep` |

---

### 4.7 Report Generation Module

#### FR-4.7.1 Report Types

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.7.1.1 | System shall generate full analysis report | Critical |
| FR-4.7.1.2 | System shall generate threats-only report | Medium |
| FR-4.7.1.3 | System shall generate compliance-only report | Medium |
| FR-4.7.1.4 | System shall generate DevSecOps rules report | Medium |

#### FR-4.7.2 Export Formats

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.7.2.1 | System shall export reports in PDF format | High |
| FR-4.7.2.2 | System shall export reports in JSON format | High |
| FR-4.7.2.3 | System shall export reports in Markdown format | High |
| FR-4.7.2.4 | Exported files shall be downloadable via browser | High |
| FR-4.7.2.5 | System shall include metadata in exported files | Medium |

#### FR-4.7.3 Report Content

| Section | Contents | Included By Default |
|---------|----------|---------------------|
| Executive Summary | Overview, key findings, risk summary | Yes |
| Threat Findings | Full threat details with DREAD scores | Yes |
| Compliance Mappings | NIST and ASVS control mappings | Yes |
| Data Flow Diagram | Mermaid diagram with annotations | Yes |
| DevSecOps Rules | Generated scanning rules | Yes |
| Mitigations | Recommended security controls | Yes |
| OWASP References | External reference citations | Yes |
| Appendix | Methodology reference | Optional |

#### FR-4.7.4 OWASP Reference Citations

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.7.4.1 | System shall include OWASP reference citations in reports | High |
| FR-4.7.4.2 | References shall be mapped deterministically (no hallucination) | Critical |
| FR-4.7.4.3 | References shall only be applied when mapping rules match | Critical |
| FR-4.7.4.4 | Unmapped findings shall be flagged for manual review | High |
| FR-4.7.4.5 | Reference format shall vary by report type | High |

#### FR-4.7.5 Reference Library (Canonical Sources)

| Reference ID | Title | URL |
|--------------|-------|-----|
| OWASP_TOP10_2025 | OWASP Top 10:2025 | https://owasp.org/Top10/2025/ |
| OWASP_LLM_TOP10 | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ |
| OWASP_AGENTIC_THREATS | Agentic AI Threats | https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/ |
| OWASP_AGENTIC_TOP10_2026 | OWASP Top 10 for Agentic Apps | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| OWASP_GENAI_INITIATIVES | GenAI Security Initiatives | https://genai.owasp.org/initiatives/ |
| OWASP_GENAI_REDTEAM | GenAI Red Teaming Guide | https://genai.owasp.org/resource/genai-red-teaming-guide/ |

#### FR-4.7.6 Reference Mapping by Report Type

| Report Type | Reference Behavior |
|-------------|-------------------|
| Full | All finding references + External References appendix |
| Executive | Top 5-10 finding references + Standards & Guidance summary |
| Technical | All finding references + OWASP Mapping Methodology notes |
| Compliance | Control/Governance references + Finding-to-Reference mapping table |

#### FR-4.7.7 Deterministic Mapping Rules

| Finding Attribute | Mapped References |
|-------------------|-------------------|
| MAESTRO category (AGENT01-06) | OWASP_AGENTIC_THREATS, OWASP_AGENTIC_TOP10_2026 |
| LLM/AI keywords detected | OWASP_LLM_TOP10 |
| Agentic/autonomous keywords | OWASP_AGENTIC_THREATS, OWASP_AGENTIC_TOP10_2026 |
| Web app security keywords | OWASP_TOP10_2025 |
| API security keywords | OWASP_API_TOP10_2023 |
| STRIDE categories | OWASP_TOP10_2025, OWASP_API_TOP10_2023 |

---

### 4.8 Conversational Analysis Module (AI Architect)

#### FR-4.8.1 Chat Interface

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.8.1.1 | System shall provide chat interface for system description | High |
| FR-4.8.1.2 | System shall maintain conversation context across messages | Critical |
| FR-4.8.1.3 | System shall display AI responses in real-time (streaming) | Medium |
| FR-4.8.1.4 | User shall be able to review conversation history | Medium |
| FR-4.8.1.5 | System shall support multi-turn conversations | Critical |

#### FR-4.8.2 Elicitation Process

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.8.2.1 | AI shall ask clarifying questions about system architecture | Critical |
| FR-4.8.2.2 | AI shall identify gaps in provided information | High |
| FR-4.8.2.3 | AI shall guide user through threat identification | High |
| FR-4.8.2.4 | AI shall progressively build threat model from conversation | Critical |
| FR-4.8.2.5 | AI shall summarize findings before finalizing analysis | High |

#### FR-4.8.3 Output Generation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.8.3.1 | System shall generate threat findings from conversation | Critical |
| FR-4.8.3.2 | System shall generate DFD from conversation | High |
| FR-4.8.3.3 | System shall allow export of conversation-based analysis | High |

---

### 4.9 Settings and Configuration Module

#### FR-4.9.1 LLM Provider Configuration

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.9.1.1 | User shall select LLM provider from supported list | Critical |
| FR-4.9.1.2 | User shall configure API key for selected provider | Critical |
| FR-4.9.1.3 | User shall select specific model for provider | High |
| FR-4.9.1.4 | Settings shall persist across browser sessions | High |
| FR-4.9.1.5 | System shall validate API key connectivity | Medium |

#### FR-4.9.2 Supported LLM Providers

| Provider | Models | API Key Required |
|----------|--------|------------------|
| OpenAI | GPT-4, GPT-4-turbo, GPT-3.5-turbo | Yes |
| Anthropic | Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku | Yes |
| OpenRouter | 100+ models | Yes |
| Google Gemini | Gemini 1.5 Pro, Gemini 1.5 Flash | Yes |
| Google Vertex AI | Gemini models (GCP) | Yes (Service Account) |
| AWS Bedrock | Claude models | Yes (AWS Credentials) |
| Ollama | Local models (Llama, Mistral, etc.) | No |
| LM Studio | Local models | No |

#### FR-4.9.3 Analysis Configuration

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.9.3.1 | User shall toggle inclusion of DFD generation | Medium |
| FR-4.9.3.2 | User shall toggle inclusion of compliance mapping | Medium |
| FR-4.9.3.3 | User shall toggle inclusion of DevSecOps rules | Medium |
| FR-4.9.3.4 | User shall configure reasoning depth (fast/balanced/deep) | Medium |

#### FR-4.9.4 Search Provider Configuration

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.9.4.1 | User shall select web search provider | Low |
| FR-4.9.4.2 | System shall support SearXNG (default) | Medium |
| FR-4.9.4.3 | System shall support Tavily, Serper, Brave, Bing | Low |

---

### 4.10 API Module

#### FR-4.10.1 Document Ingestion API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ingest` | POST | Upload documents and create project |
| `/api/ingest` | GET | List all projects |
| `/api/ingest/{project_id}` | GET | Get project details |
| `/api/ingest/{project_id}` | DELETE | Delete project |

#### FR-4.10.2 Analysis API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze` | POST | Start threat analysis |
| `/api/analyze/list` | GET | List all analyses with project names |
| `/api/analyze/{analysis_id}/status` | GET | Get analysis progress |
| `/api/analyze/{analysis_id}` | GET | Get analysis results |

#### FR-4.10.2.1 Analysis List Response

```json
{
  "analyses": [
    {
      "id": "uuid",
      "project_id": "uuid",
      "project_name": "string",
      "project_description": "string | null",
      "methodology": "stride | pasta",
      "status": "string",
      "created_at": "ISO8601",
      "completed_at": "ISO8601 | null",
      "threats_count": "integer"
    }
  ]
}
```

#### FR-4.10.3 Threat API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/threats/{analysis_id}` | GET | Get threats for analysis |
| `/api/threats/{threat_id}` | GET | Get specific threat details |

#### FR-4.10.4 DFD API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dfd/generate` | POST | Generate DFD |
| `/api/dfd/{analysis_id}` | GET | Get DFD for analysis |

#### FR-4.10.5 Report API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/report/generate` | POST | Generate report |
| `/api/report/{report_id}` | GET | Get report |

#### FR-4.10.6 Export API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/export/pdf` | POST | Export as PDF |
| `/api/export/json` | POST | Export as JSON |
| `/api/export/markdown` | POST | Export as Markdown |

#### FR-4.10.7 Settings API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/settings` | GET | Get current settings |
| `/api/settings` | PUT | Update settings |

#### FR-4.10.8 Architect Chat API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/architect-chat/send` | POST | Send message to AI architect |

#### FR-4.10.9 Health API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | System health check |
| `/` | GET | API information |

---

## 5. Non-Functional Requirements

### 5.1 Performance Requirements

| ID | Requirement | Target | Priority |
|----|-------------|--------|----------|
| NFR-5.1.1 | API response time (non-AI endpoints) | < 200ms | High |
| NFR-5.1.2 | File upload processing time | < 5s per 10MB file | High |
| NFR-5.1.3 | Threat analysis completion time | < 10 minutes for standard project | Medium |
| NFR-5.1.4 | DFD generation time | < 30 seconds | Medium |
| NFR-5.1.5 | Report generation time | < 60 seconds | Medium |
| NFR-5.1.6 | Concurrent analysis support | 5 simultaneous analyses | Medium |

### 5.2 Scalability Requirements

| ID | Requirement | Target | Priority |
|----|-------------|--------|----------|
| NFR-5.2.1 | Maximum file size | 10MB (configurable to 100MB) | High |
| NFR-5.2.2 | Maximum files per project | 50 files | Medium |
| NFR-5.2.3 | Maximum threats per analysis | 500 | Medium |
| NFR-5.2.4 | Storage capacity | 10GB default | Medium |

### 5.3 Availability Requirements

| ID | Requirement | Target | Priority |
|----|-------------|--------|----------|
| NFR-5.3.1 | System uptime | 99.5% | High |
| NFR-5.3.2 | Planned maintenance window | < 4 hours/month | Medium |
| NFR-5.3.3 | Recovery time objective (RTO) | < 1 hour | Medium |
| NFR-5.3.4 | Recovery point objective (RPO) | < 24 hours | Medium |

### 5.4 Usability Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NFR-5.4.1 | System shall be accessible via modern web browsers (Chrome, Firefox, Safari, Edge) | High |
| NFR-5.4.2 | System shall support dark and light themes | Medium |
| NFR-5.4.3 | System shall provide clear error messages | High |
| NFR-5.4.4 | System shall provide loading indicators for async operations | High |
| NFR-5.4.5 | System shall be responsive (desktop-first) | Medium |

### 5.5 Compatibility Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NFR-5.5.1 | Backend shall run on Python 3.11+ | Critical |
| NFR-5.5.2 | Frontend shall run on Node.js 18+ | Critical |
| NFR-5.5.3 | System shall deploy via Docker containers | High |
| NFR-5.5.4 | System shall support Linux, macOS, Windows hosts | High |

---

## 6. System Architecture

### 6.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Frontend Layer                                  │
│                           (Next.js 14 / React 18)                           │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ │
│  │  Home   │ │ Upload  │ │Architect│ │ Review  │ │   DFD   │ │AI Architect│ │
│  │  Page   │ │  Page   │ │  Page   │ │  Page   │ │  Page   │ │   Page    │ │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └───────────┘ │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Shared Components                                 │  │
│  │  [Navbar] [Settings Modal] [Theme Toggle] [Export Modal] [DFD Editor]│  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  State: Zustand Stores    │    Data Fetching: TanStack React Query         │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     │ REST API (HTTP/JSON)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Backend Layer                                   │
│                            (FastAPI / Python)                               │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                          API Routers                                  │  │
│  │  /ingest  /analyze  /threats  /dfd  /report  /export  /settings     │  │
│  │  /architect-chat  /mcp  /health                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     LangGraph Agent Orchestrator                      │  │
│  │                                                                       │  │
│  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │  │
│  │   │  Elicitation │───►│   Threat     │───►│  Compliance  │          │  │
│  │   │    Agent     │    │    Agent     │    │    Agent     │          │  │
│  │   └──────────────┘    └──────────────┘    └──────────────┘          │  │
│  │          │                                        │                  │  │
│  │          │            ┌──────────────┐           │                  │  │
│  │          │            │  Guardrail   │◄──────────┘                  │  │
│  │          │            │    Agent     │                              │  │
│  │          │            └──────────────┘                              │  │
│  │          ▼                    ▲                                      │  │
│  │   ┌──────────────┐    ┌──────────────┐                              │  │
│  │   │   Diagram    │───►│  DevSecOps   │──────────────────────────────┘  │
│  │   │    Agent     │    │    Agent     │                                 │
│  │   └──────────────┘    └──────────────┘                                 │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                      Threat Modeling Engines                          │  │
│  │  [STRIDE Engine]  [PASTA Engine]  [DREAD Scorer]  [Compliance Mapper]│  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                          Service Layer                                │  │
│  │  [LLM Provider]  [Document Parser]  [Embedding Provider]             │  │
│  │  [Web Search]    [MCP Client]       [Reasoning Engine]               │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                           │                    │
              ┌────────────┴────────┐    ┌─────┴─────────────┐
              ▼                     ▼    ▼                   ▼
┌─────────────────────┐  ┌───────────────────┐  ┌───────────────────────────┐
│    File Storage     │  │   Graph Database  │  │     Vector Database       │
│                     │  │     (Neo4j)       │  │       (Qdrant)            │
│  ./uploads/         │  │                   │  │                           │
│  ./data/projects/   │  │  Threat Graph     │  │  Document Embeddings      │
│  ./data/analyses/   │  │  Relationships    │  │  Semantic Search          │
│  ./data/reports/    │  │                   │  │                           │
│  ./logs/            │  │  (Optional)       │  │  (Optional)               │
└─────────────────────┘  └───────────────────┘  └───────────────────────────┘
```

### 6.2 Agent Workflow (LangGraph StateGraph)

```
                          ┌─────────────┐
                          │    START    │
                          └──────┬──────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Elicitation Agent    │
                    │  (Gap Identification)  │
                    └────────────┬───────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │     Threat Agent       │
                    │  (STRIDE/PASTA)        │
                    └────────────┬───────────┘
                                 │
                    ┌────────────┴────────────┐
                    │    include_compliance?  │
                    └────────────┬────────────┘
                          Yes    │    No
                    ┌────────────┴────────────┐
                    ▼                         │
         ┌──────────────────┐                 │
         │ Compliance Agent │                 │
         │ (NIST/ASVS)      │                 │
         └────────┬─────────┘                 │
                  │                           │
                  └─────────────┬─────────────┘
                                │
                    ┌───────────┴───────────┐
                    │      include_dfd?     │
                    └───────────┬───────────┘
                          Yes   │   No
                    ┌───────────┴───────────┐
                    ▼                       │
         ┌──────────────────┐               │
         │  Diagram Agent   │               │
         │  (Mermaid DFD)   │               │
         └────────┬─────────┘               │
                  │                         │
                  └─────────┬───────────────┘
                            │
                ┌───────────┴────────────┐
                │   include_devsecops?   │
                └───────────┬────────────┘
                      Yes   │   No
                ┌───────────┴────────────┐
                ▼                        │
     ┌──────────────────┐                │
     │ DevSecOps Agent  │                │
     │ (Rules Gen)      │                │
     └────────┬─────────┘                │
              │                          │
              └─────────┬────────────────┘
                        │
                        ▼
           ┌────────────────────────┐
           │    Guardrail Agent     │
           │  (Validation)          │
           └────────────┬───────────┘
                        │
                        ▼
           ┌────────────────────────┐
           │       Finalize         │
           │  (Output Assembly)     │
           └────────────┬───────────┘
                        │
                        ▼
                  ┌───────────┐
                  │    END    │
                  └───────────┘
```

### 6.3 Component Dependencies

```
Frontend (Next.js)
├── React 18
├── TypeScript 5.7
├── Tailwind CSS 3.4
├── Zustand 5.0 (State)
├── TanStack Query 5.62 (Data Fetching)
├── Framer Motion 11.15 (Animations)
├── Mermaid 10.9 (Diagrams)
└── Lucide React (Icons)

Backend (FastAPI)
├── Python 3.11+
├── FastAPI 0.115+
├── LangGraph 0.2+
├── LangChain 0.3+
├── Pydantic 2.10+
├── aiofiles (Async I/O)
├── httpx (HTTP Client)
├── structlog (Logging)
├── unstructured (Document Parsing)
├── bleach (Sanitization)
└── tenacity (Retry Logic)

LLM Integrations
├── openai (OpenAI SDK)
├── anthropic (Anthropic SDK)
├── google-generativeai (Gemini)
├── google-cloud-aiplatform (Vertex AI)
├── boto3 (AWS Bedrock)
└── ollama (Local Models)

Databases (Optional)
├── neo4j (Graph DB)
└── qdrant-client (Vector DB)
```

---

## 7. Data Requirements

### 7.1 Data Models

#### 7.1.1 Project Model

```json
{
  "id": "uuid",
  "name": "string",
  "description": "string | null",
  "status": "enum: created | ingested | analyzing | completed | failed",
  "files": [
    {
      "original_name": "string",
      "safe_name": "string",
      "size": "integer",
      "hash": "string (SHA256)",
      "mime_type": "string"
    }
  ],
  "metadata": {
    "upload_time": "ISO8601 datetime"
  },
  "source": "string | null (upload | architect | api)",
  "architecture_types": ["array of strings (web, mobile, api, microservices, etc.)"],
  "methodology": "string | null (stride | pasta)",
  "created_at": "ISO8601 datetime",
  "updated_at": "ISO8601 datetime"
}
```

#### 7.1.2 Analysis Model

```json
{
  "id": "uuid",
  "project_id": "uuid",
  "methodology": "enum: stride | pasta",
  "status": "enum: pending | in_progress | completed | failed",
  "config": {
    "include_dfd": "boolean",
    "include_compliance": "boolean",
    "include_devsecops": "boolean",
    "reasoning_level": "enum: fast | balanced | deep"
  },
  "threats": ["array of Threat objects"],
  "compliance_summary": {
    "NIST_800_53": { "coverage": {}, "gaps": [] },
    "OWASP_ASVS": { "coverage": {}, "gaps": [] }
  },
  "dfd_mermaid": "string (Mermaid code)",
  "devsecops_rules": {
    "checkov": [],
    "tfsec": [],
    "semgrep": []
  },
  "created_at": "ISO8601 datetime",
  "completed_at": "ISO8601 datetime | null",
  "error_message": "string | null"
}
```

#### 7.1.3 Threat Model

```json
{
  "id": "uuid",
  "category": "string (STRIDE category or PASTA stage)",
  "title": "string",
  "description": "string",
  "affected_component": "string",
  "attack_vector": "string",
  "severity": "enum: critical | high | medium | low",
  "dread_score": {
    "damage": "integer (1-10)",
    "reproducibility": "integer (1-10)",
    "exploitability": "integer (1-10)",
    "affected_users": "integer (1-10)",
    "discoverability": "integer (1-10)",
    "overall": "float",
    "priority": "enum: critical | high | medium | low"
  },
  "mitigations": ["array of strings"],
  "compliance_mappings": {
    "NIST": ["array of control IDs"],
    "ASVS": ["array of requirement IDs"]
  }
}
```

#### 7.1.4 Report Model

```json
{
  "id": "uuid",
  "project_id": "uuid",
  "analysis_id": "uuid",
  "report_type": "enum: full | threats | compliance | devsecops",
  "format": "enum: pdf | json | markdown",
  "content": "object",
  "file_path": "string",
  "created_at": "ISO8601 datetime"
}
```

### 7.2 Data Storage

| Data Type | Storage Location | Retention |
|-----------|------------------|-----------|
| Projects | `./data/projects/{id}.json` | Until deleted |
| Analyses | `./data/analyses/{id}.json` | Until deleted |
| Reports | `./data/reports/{id}.json` | Until deleted |
| Exports | `./data/exports/{filename}` | Until deleted |
| Uploads | `./uploads/{project_id}/{filename}` | Until project deleted |
| Logs | `./logs/` | 30 days (configurable) |

### 7.3 Data Integrity

| ID | Requirement | Implementation |
|----|-------------|----------------|
| DR-7.3.1 | File integrity verification | SHA256 hash on upload |
| DR-7.3.2 | Atomic file writes | Write to temp, then rename |
| DR-7.3.3 | Backup capability | File-based storage allows standard backup |

---

## 8. Interface Requirements

### 8.1 User Interface Requirements

#### 8.1.1 Navigation

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-8.1.1.1 | Global navigation bar on all pages | High |
| UI-8.1.1.2 | Links to: Home, Upload, Architect, Review, DFD, AI Architect | High |
| UI-8.1.1.3 | Settings access from navigation | High |
| UI-8.1.1.4 | Theme toggle in navigation | Medium |

#### 8.1.2 Home Page

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-8.1.2.1 | Feature overview section | Medium |
| UI-8.1.2.2 | How-it-works explanation | Medium |
| UI-8.1.2.3 | CTA buttons to start analysis | High |
| UI-8.1.2.4 | LLM provider quick selection | Medium |

#### 8.1.3 Upload Page

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-8.1.3.1 | Drag-and-drop upload zone | High |
| UI-8.1.3.2 | File browser button | High |
| UI-8.1.3.3 | File list with remove option | High |
| UI-8.1.3.4 | Methodology selector (STRIDE/PASTA) | High |
| UI-8.1.3.5 | Start analysis button | High |
| UI-8.1.3.6 | Backend connectivity indicator | High |

#### 8.1.4 Review Page

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-8.1.4.1 | Threat findings table | High |
| UI-8.1.4.2 | Threat detail view | High |
| UI-8.1.4.3 | DREAD score display | High |
| UI-8.1.4.4 | Compliance mappings view | High |
| UI-8.1.4.5 | DevSecOps rules view | High |
| UI-8.1.4.6 | Export options | High |
| UI-8.1.4.7 | Analysis history selector dropdown | High |
| UI-8.1.4.8 | Display project name in header | High |
| UI-8.1.4.9 | Display analysis timestamps (created, completed) | Medium |
| UI-8.1.4.10 | Display truncated analysis ID | Medium |
| UI-8.1.4.11 | Navigate to DFD for current analysis | High |
| UI-8.1.4.12 | Filter analyses by methodology | Medium |
| UI-8.1.4.13 | Search analyses by project name | Medium |

#### 8.1.5 DFD Page

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-8.1.5.1 | Mermaid diagram renderer | High |
| UI-8.1.5.2 | Source code editor | Medium |
| UI-8.1.5.3 | Zoom/pan controls | Medium |
| UI-8.1.5.4 | Export as image (PNG, SVG) | Medium |
| UI-8.1.5.5 | Display project name in header | High |
| UI-8.1.5.6 | Display methodology badge (STRIDE/PASTA) | Medium |
| UI-8.1.5.7 | Display threat count | Medium |
| UI-8.1.5.8 | Display analysis timestamps | Medium |
| UI-8.1.5.9 | Navigate to Review page for current analysis | High |
| UI-8.1.5.10 | Auto-load most recent analysis if none specified | Medium |

#### 8.1.6 AI Architect Page

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-8.1.6.1 | Chat message input | High |
| UI-8.1.6.2 | Conversation history display | High |
| UI-8.1.6.3 | AI response streaming | Medium |
| UI-8.1.6.4 | Generate analysis button | High |

#### 8.1.7 Settings Modal

| ID | Requirement | Priority |
|----|-------------|----------|
| UI-8.1.7.1 | LLM provider dropdown | High |
| UI-8.1.7.2 | API key input (masked) | High |
| UI-8.1.7.3 | Model selector | High |
| UI-8.1.7.4 | Search provider config | Low |
| UI-8.1.7.5 | Reasoning depth selector | Medium |
| UI-8.1.7.6 | Save/Cancel buttons | High |

### 8.2 API Interface Requirements

#### 8.2.1 Request/Response Format

| ID | Requirement | Priority |
|----|-------------|----------|
| API-8.2.1.1 | All requests/responses in JSON format | Critical |
| API-8.2.1.2 | UTF-8 encoding for all text | Critical |
| API-8.2.1.3 | ISO 8601 format for all timestamps | High |
| API-8.2.1.4 | UUID format for all identifiers | High |

#### 8.2.2 API Headers

| Header | Purpose | Required |
|--------|---------|----------|
| `Content-Type` | Request body format | Yes (for POST/PUT) |
| `Accept` | Response format | No (defaults to JSON) |
| `X-API-Key` | Authentication | Optional |
| `X-Request-ID` | Request tracking | No (auto-generated) |

#### 8.2.3 Error Response Format

```json
{
  "detail": "string (error message)",
  "error_code": "string (optional)",
  "request_id": "string"
}
```

---

## 9. Security Requirements

### 9.1 Input Validation

| ID | Requirement | Priority |
|----|-------------|----------|
| SEC-9.1.1 | Validate all file uploads (type, size, name) | Critical |
| SEC-9.1.2 | Sanitize all user input | Critical |
| SEC-9.1.3 | Validate JSON/YAML structure before parsing | High |
| SEC-9.1.4 | Reject requests with invalid content types | High |

### 9.2 Authentication and Authorization

| ID | Requirement | Priority |
|----|-------------|----------|
| SEC-9.2.1 | Support optional API key authentication | Medium |
| SEC-9.2.2 | Rate limit requests per IP | High |
| SEC-9.2.3 | Log authentication failures | High |

### 9.3 Data Protection

| ID | Requirement | Priority |
|----|-------------|----------|
| SEC-9.3.1 | Do not log sensitive data (API keys, file contents) | Critical |
| SEC-9.3.2 | Encrypt API keys at rest (frontend localStorage) | Medium |
| SEC-9.3.3 | Secure file permissions (0o640) for uploaded files | High |
| SEC-9.3.4 | Sanitize filenames before storage | Critical |

### 9.4 Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | nosniff | Prevent MIME sniffing |
| `X-Frame-Options` | DENY | Prevent clickjacking |
| `X-XSS-Protection` | 1; mode=block | XSS protection |
| `Referrer-Policy` | strict-origin-when-cross-origin | Referrer control |
| `Cache-Control` | no-store | Prevent caching of API responses |
| `Permissions-Policy` | geolocation=(), microphone=(), camera=() | Feature restrictions |

### 9.5 Rate Limiting

| ID | Requirement | Default | Priority |
|----|-------------|---------|----------|
| SEC-9.5.1 | Rate limit per IP address | 60 req/min | High |
| SEC-9.5.2 | Configurable rate limit threshold | Yes | Medium |
| SEC-9.5.3 | Return 429 status on rate limit exceeded | Yes | High |

---

## 10. Error Handling

### 10.1 Error Categories

| Category | HTTP Status | Description | User Message |
|----------|-------------|-------------|--------------|
| file_error | 400 | File processing failed | "There was a problem processing your file" |
| validation_error | 400 | Invalid input data | "The provided data is invalid" |
| not_found | 404 | Resource not found | "The requested resource was not found" |
| rate_limit | 429 | Too many requests | "Too many requests. Please wait and try again" |
| llm_error | 500/503 | LLM provider issue | "AI service temporarily unavailable" |
| configuration | 500 | Missing config | "System configuration error" |
| database | 500 | Storage error | "Database operation failed" |
| internal | 500 | Unexpected error | "An unexpected error occurred" |

### 10.1.2 Error Response Structure

```json
{
  "title": "string (human-readable error title)",
  "detail": "string (user-friendly message)",
  "category": "string (error category enum)",
  "status_code": "integer",
  "context": {
    "resource_type": "string (optional)",
    "resource_id": "string (optional)"
  }
}
```

### 10.2 Error Handling Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| ERR-10.2.1 | Return structured error responses | High |
| ERR-10.2.2 | Include request ID in error responses | High |
| ERR-10.2.3 | Log all errors with stack traces | High |
| ERR-10.2.4 | Do not expose internal details in client errors | Critical |
| ERR-10.2.5 | Implement retry logic for transient LLM failures | High |
| ERR-10.2.6 | Graceful degradation when optional services unavailable | Medium |

### 10.3 Retry Configuration

| Service | Max Retries | Initial Delay | Backoff |
|---------|-------------|---------------|---------|
| LLM Provider | 3 | 1 second | Exponential (2x) |
| Neo4j | 3 | 0.5 seconds | Exponential (2x) |
| Qdrant | 3 | 0.5 seconds | Exponential (2x) |
| File Operations | 2 | 0.1 seconds | Linear |

---

## Appendices

### Appendix A: API Endpoint Reference

#### A.1 Document Ingestion

**POST /api/ingest**

Request:
```
Content-Type: multipart/form-data

files: File[] (required)
project_name: string (optional)
description: string (optional)
```

Response (201):
```json
{
  "project_id": "uuid",
  "status": "ingested",
  "files_processed": 3,
  "message": "Project created successfully"
}
```

**GET /api/ingest**

Response (200):
```json
{
  "projects": [
    {
      "id": "uuid",
      "name": "string",
      "status": "string",
      "file_count": 3,
      "created_at": "ISO8601"
    }
  ],
  "total": 10,
  "page": 1,
  "per_page": 20
}
```

#### A.2 Analysis

**POST /api/analyze**

Request:
```json
{
  "project_id": "uuid",
  "methodology": "stride | pasta",
  "include_dfd": true,
  "include_compliance": true,
  "include_devsecops": true
}
```

Response (202):
```json
{
  "analysis_id": "uuid",
  "status": "pending",
  "message": "Analysis started"
}
```

**GET /api/analyze/{analysis_id}/status**

Response (200):
```json
{
  "analysis_id": "uuid",
  "status": "in_progress",
  "progress": 45,
  "current_stage": "threat_analysis",
  "stages_completed": ["elicitation"]
}
```

#### A.3 Export

**POST /api/export/pdf**

Request:
```json
{
  "analysis_id": "uuid",
  "include_sections": ["threats", "compliance", "dfd", "devsecops"]
}
```

Response (200):
```json
{
  "download_url": "/exports/{filename}.pdf",
  "filename": "security_report_{timestamp}.pdf",
  "size": 1024576
}
```

### Appendix B: STRIDE Threat Categories

| Category | Description | Security Property | Example Mitigation |
|----------|-------------|-------------------|-------------------|
| **Spoofing** | Impersonating something or someone | Authentication | Strong authentication, MFA |
| **Tampering** | Modifying data or code | Integrity | Input validation, digital signatures |
| **Repudiation** | Denying performed actions | Non-repudiation | Audit logging, digital signatures |
| **Information Disclosure** | Exposing information | Confidentiality | Encryption, access controls |
| **Denial of Service** | Denying or degrading service | Availability | Rate limiting, redundancy |
| **Elevation of Privilege** | Gaining unauthorized capabilities | Authorization | Least privilege, RBAC |

### Appendix C: PASTA Stages

| Stage | Description | Key Activities |
|-------|-------------|----------------|
| **Stage 1** | Define Business Objectives | Identify business impact, risk appetite |
| **Stage 2** | Define Technical Scope | Document application architecture |
| **Stage 3** | Decompose Application | Create DFDs, identify trust boundaries |
| **Stage 4** | Analyze Threats | Enumerate threat scenarios |
| **Stage 5** | Identify Vulnerabilities | Map threats to weaknesses |
| **Stage 6** | Enumerate Attacks | Model attack trees |
| **Stage 7** | Risk/Impact Analysis | Calculate risk scores, prioritize |

### Appendix D: DREAD Scoring Guide

| Factor | 1-3 (Low) | 4-6 (Medium) | 7-10 (High) |
|--------|-----------|--------------|-------------|
| **Damage** | Minor inconvenience | Data loss, financial impact | Critical system compromise |
| **Reproducibility** | Difficult to reproduce | Can reproduce with effort | Easily reproducible |
| **Exploitability** | Requires expert skills | Requires moderate skills | Script kiddie can exploit |
| **Affected Users** | Individual users | Subset of users | All users |
| **Discoverability** | Requires deep analysis | Discoverable with tools | Publicly known |

### Appendix E: Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-14 | PadmaVue.ai Team | Initial document creation |
| 1.1 | 2026-01-15 | PadmaVue.ai Team | Updated Project data model with source, architecture_types, methodology fields; Added analysis list API with project names; Added analysis history UI requirements (UI-8.1.4.7-13); Added DFD page context requirements (UI-8.1.5.5-10); Enhanced error categories with user messages and response structure; Updated status to Active |

---

## Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Product Owner | | | |
| Technical Lead | | | |
| Security Architect | | | |
| QA Lead | | | |
