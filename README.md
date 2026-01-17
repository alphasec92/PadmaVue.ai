# 🛡️ PadmaVue.ai

**AI-Powered Security Review Platform** — Automated threat modeling, compliance mapping, and DevSecOps rule generation.

---

## 🚀 Quick Start

### Mac / Linux
```bash
chmod +x start.sh
./start.sh
```

### Windows (PowerShell)
```powershell
.\start.ps1
```

**That's it!** Open http://localhost:3000

> **First run?** Dependencies will be installed automatically (2-3 minutes).

---

## 📦 Two Modes

| Mode | What's Included | Best For |
|------|-----------------|----------|
| **Lite** (default) | Backend + Frontend | Quick demos, development |
| **Full** | + Neo4j + Qdrant | Production, large projects |

```bash
# Lite mode (default)
./start.sh

# Full mode (requires Docker)
./start.sh --full
```

---

## 🔄 How It Works

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Upload     │───▶│  Elicitation │───▶│     DFD      │───▶│   Threats    │
│  Documents   │    │  Questions   │    │  Generation  │    │   + Report   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

1. **Ingest** — Upload architecture docs, configs, or code
2. **Elicitation** — AI asks clarifying questions about your system
3. **DFD Generation** — Auto-generates data flow diagrams (Mermaid)
4. **Threat Analysis** — STRIDE/PASTA analysis with DREAD scoring
5. **Report** — Compliance mappings (NIST 800-53, OWASP ASVS) + DevSecOps rules

---

## 📋 Requirements

| Requirement | Version | Check |
|-------------|---------|-------|
| Python | 3.11+ | `python3 --version` |
| Node.js | **20.9+** | `node --version` |
| npm | 10+ | `npm --version` |
| Docker | (Full mode only) | `docker --version` |

> ⚠️ **Node.js 20.9+** is required for Next.js 16. Use `nvm install 20` to upgrade.

### Install Dependencies

**macOS:**
```bash
brew install python@3.11 node@20
# Or use nvm:
nvm install 20 && nvm use 20
```

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install python3.11 python3.11-venv
# Install Node.js 20 via nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
nvm install 20
```

**Windows:**
```powershell
winget install Python.Python.3.11
winget install OpenJS.NodeJS
```

---

## 🎯 Usage

### Start Commands

| Command | Mode | Description |
|---------|------|-------------|
| `./start.sh` | Lite | Backend + Frontend |
| `./start.sh --full` | Full | + Neo4j + Qdrant (Docker) |
| `./start.sh --backend` | Lite | Backend only |
| `./start.sh --frontend` | Lite | Frontend only |
| `./start.sh --reset` | - | Clean reinstall |

**Windows:** Replace `./start.sh` with `.\start.ps1` and `--` with `-` (e.g., `.\start.ps1 -Full`)

### Stop Commands

```bash
./stop.sh              # Mac/Linux
.\stop.ps1             # Windows
# Or press Ctrl+C
```

---

## 🐳 Docker

### ⚡ Quick Start with Pre-built Images (Recommended)

**No building required!** Pull and run pre-built images directly:

```bash
# Download the compose file
curl -fsSL https://raw.githubusercontent.com/kjangiti/PandmaVue.ai/main/infra/docker/compose/docker-compose.hub.yml -o docker-compose.yml

# Start everything
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

### Build from Source

#### Lite Mode (No databases)
```bash
docker compose -f infra/docker/compose/compose.lite.yml up --build -d
docker compose -f infra/docker/compose/compose.lite.yml logs -f
docker compose -f infra/docker/compose/compose.lite.yml down
```

#### Full Mode (With Neo4j + Qdrant)
```bash
docker compose -f infra/docker/compose/compose.full.yml up --build -d
docker compose -f infra/docker/compose/compose.full.yml logs -f
docker compose -f infra/docker/compose/compose.full.yml down
```

> **Note:** If `docker compose` fails, try `docker-compose` (older Docker versions).

### Services (Full Mode)

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend | http://localhost:8000 |
| Neo4j | http://localhost:7474 |
| Qdrant | http://localhost:6333 |

### Docker Images

Pre-built images available on GitHub Container Registry:

| Image | Pull Command |
|-------|--------------|
| Backend | `docker pull ghcr.io/kjangiti/pandmavue.ai/backend:latest` |
| Frontend | `docker pull ghcr.io/kjangiti/pandmavue.ai/frontend:latest` |

**Tags available:**
- `latest` — Latest stable build from main branch
- `v1.0.0` — Specific version (semantic versioning)
- `sha-abc123` — Specific commit

---

## 🤖 AI Provider Setup

Default: **Mock Mode** (no AI needed, sample responses)

### Option 1: Ollama (Free, Local) ⭐ Recommended

**Mac/Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
ollama serve
```

**Windows:**
1. Download from https://ollama.com
2. Run: `ollama pull llama3.2`
3. Run: `ollama serve`

### Option 2: LM Studio (Free, Local)
1. Download from https://lmstudio.ai
2. Load a model → Start local server

### Option 3: Cloud Providers
Configure via **⚙️ Settings** in the app:
- OpenAI (GPT-4)
- Anthropic (Claude)
- OpenRouter (100+ models)
- Google Gemini
- AWS Bedrock

---

## 🔒 Data Handling & Privacy

### What's Stored Locally
- Uploaded documents (`./uploads/`)
- Analysis results (`./data/`)
- Logs (`./logs/`)

### What's Sent to AI Providers
- **Mock Mode**: Nothing (offline)
- **Ollama/LM Studio**: Nothing (local AI)
- **Cloud Providers**: Document content for analysis

### Running Fully Offline
1. Use Mock Mode, Ollama, or LM Studio
2. Use Lite Mode (no external databases)

---

## 📊 API Examples

```bash
# Health check
curl http://localhost:8000/health

# Upload a document
curl -X POST http://localhost:8000/api/ingest \
  -F "files=@architecture.pdf" \
  -F "project_name=MyProject"

# Run analysis
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"project_id": "your-project-id", "methodology": "stride"}'
```

**Full API Docs:** http://localhost:8000/docs

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Frontend (Next.js)                       │
│                 http://localhost:3000                    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  Backend (FastAPI)                       │
│                 http://localhost:8000                    │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │ Elicitation │ │   Threat    │ │ Compliance  │       │
│  │    Agent    │ │    Agent    │ │    Agent    │       │
│  └─────────────┘ └─────────────┘ └─────────────┘       │
│             LangGraph Orchestrator                       │
└─────────────────────────────────────────────────────────┘
          │ (Full Mode only)          │
          ▼                           ▼
┌───────────────────┐      ┌───────────────────┐
│  Neo4j (GraphRAG) │      │ Qdrant (VectorRAG)│
│  localhost:7474   │      │  localhost:6333   │
└───────────────────┘      └───────────────────┘
```

---

## 📁 Project Structure

```
PandmaVue.ai/
├── start.sh / start.ps1           # Start scripts
├── stop.sh / stop.ps1             # Stop scripts
├── infra/
│   └── docker/
│       └── compose/               # Docker compose files
│           ├── compose.lite.yml   # Lite mode
│           ├── compose.full.yml   # Full mode
│           └── docker-compose.hub.yml
├── scripts/
│   └── common/                    # Shared script utilities
├── backend/
│   ├── app/
│   │   ├── agents/               # LangGraph AI agents
│   │   ├── api/                  # REST endpoints
│   │   └── engines/              # STRIDE, PASTA, DREAD
│   └── requirements.txt
├── frontend/
│   ├── app/                      # Next.js pages
│   ├── components/               # React components
│   └── package.json
├── docs/                         # BRD, FRD documentation
└── env-templates/                # Configuration templates
```

---

## 🔧 Configuration

Environment variables in `backend/.env`:

```bash
# Storage mode: lite (default) or full
STORAGE_MODE=lite

# LLM Provider: mock, ollama, openai, anthropic, etc.
LLM_PROVIDER=mock

# Ollama (if using)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

See `env-templates/backend.env` for all options.

---

## ❓ Troubleshooting

### "Backend not connected"
```bash
curl http://localhost:8000/health   # Should return {"status":"healthy"...}
./stop.sh && ./start.sh             # Restart
```

### "Port already in use"
```bash
# Mac/Linux
lsof -ti :8000 | xargs kill -9
lsof -ti :3000 | xargs kill -9

# Windows
.\stop.ps1
```

### "command not found: uvicorn"
```bash
cd backend && source venv/bin/activate
```

### "Execution Policy" error (Windows)
```powershell
powershell -ExecutionPolicy Bypass -File start.ps1
```

### Reset everything
```bash
./start.sh --reset
```

---

## 🔬 Features

| Feature | Description |
|---------|-------------|
| STRIDE Analysis | Systematic threat categorization |
| PASTA Methodology | 7-stage risk-centric analysis |
| MAESTRO Framework | Agentic AI threat modeling (CSA) |
| DREAD Scoring | Quantified risk (1-10 scale) |
| Compliance Mapping | NIST 800-53, OWASP ASVS |
| **OWASP Citations** | Deterministic reference mapping (no hallucination) |
| DFD Generation | Mermaid data flow diagrams |
| DevSecOps Rules | Checkov, tfsec, Semgrep |
| MCP Integration | External security tools |

### OWASP Reference Citations

Reports include deterministic mappings to OWASP guidance:

| Reference | Scope |
|-----------|-------|
| [OWASP Top 10:2025](https://owasp.org/Top10/2025/) | Web application risks |
| [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) | LLM/GenAI security |
| [OWASP Agentic AI Threats](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) | Autonomous agent risks |
| [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Agentic app Top 10 |
| [GenAI Red Teaming Guide](https://genai.owasp.org/resource/genai-red-teaming-guide/) | AI security testing |

**Hard Rules:**
- References mapped deterministically (no hallucination)
- If mapping rules don't match, findings are flagged for manual review
- No claims of compliance - guidance references only

---

## 📚 References

- [STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [PASTA](https://owasp.org/www-project-threat-model/)
- [MAESTRO (CSA)](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)
- [NIST 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP GenAI](https://genai.owasp.org/)

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔐 Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## 📄 License

MIT License - See LICENSE file.

---

Built with ❤️ by PadmaVue.ai
