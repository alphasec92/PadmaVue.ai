# PadmaVue.ai - Docker Deployment

This directory contains Docker Compose configurations for deploying PadmaVue.ai.

## Compose Files

| File | Purpose | Use Case |
|------|---------|----------|
| `compose.lite.yml` | Backend + Frontend only | Development, quick testing |
| `compose.full.yml` | Backend + Frontend + Neo4j + Qdrant | Full features, production-like |
| `docker-compose.yml` | Full with persistent storage | Production deployment |
| `docker-compose.hub.yml` | Pre-built images from GHCR | Quick deployment without building |
| `docker-compose.search.yml` | SearXNG search engine | Web-grounded AI responses |

## Quick Start

### Lite Mode (Recommended for Development)

Backend and frontend only, no external databases:

```bash
# From repository root
docker compose -f infra/docker/compose/compose.lite.yml up --build -d

# View logs
docker compose -f infra/docker/compose/compose.lite.yml logs -f

# Stop
docker compose -f infra/docker/compose/compose.lite.yml down
```

### Full Mode (All Features)

Includes Neo4j graph database and Qdrant vector database:

```bash
# From repository root
docker compose -f infra/docker/compose/compose.full.yml up --build -d

# View logs
docker compose -f infra/docker/compose/compose.full.yml logs -f

# Stop
docker compose -f infra/docker/compose/compose.full.yml down
```

### Pre-built Images (Fastest)

Use pre-built images from GitHub Container Registry:

```bash
# From repository root
docker compose -f infra/docker/compose/docker-compose.hub.yml up -d

# Stop
docker compose -f infra/docker/compose/docker-compose.hub.yml down
```

### With Web Search (SearXNG)

Add web-grounded responses for AI:

```bash
# Start SearXNG
docker compose -f infra/docker/compose/docker-compose.search.yml up -d

# Configure backend/.env:
# SEARCH_PROVIDER=searxng
# SEARXNG_BASE_URL=http://localhost:8080

# Then start PadmaVue.ai
docker compose -f infra/docker/compose/compose.lite.yml up --build -d
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 3000 | Next.js web interface |
| Backend | 8000 | FastAPI REST API |
| Neo4j | 7474, 7687 | Graph database (full mode) |
| Qdrant | 6333, 6334 | Vector database (full mode) |
| SearXNG | 8080 | Search engine (optional) |

## Environment Variables

Copy `env-templates/backend.env` to `backend/.env` and configure:

```bash
# Required
LLM_PROVIDER=ollama  # Options: mock, ollama, openai, anthropic, openrouter

# For cloud LLM providers
OPENAI_API_KEY=your-key
ANTHROPIC_API_KEY=your-key
OPENROUTER_API_KEY=your-key

# Database (full mode)
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=padmavue

# Storage mode
STORAGE_MODE=lite  # Options: lite, full
```

## Volumes

The compose files create these persistent volumes:

| Volume | Purpose |
|--------|---------|
| `backend_data` | Analysis data, projects |
| `backend_logs` | Application logs |
| `uploads_data` | Uploaded documents |
| `neo4j_data` | Graph database data |
| `qdrant_data` | Vector embeddings |

## Health Checks

All services include health checks. Check status:

```bash
docker compose -f infra/docker/compose/compose.lite.yml ps
```

## Troubleshooting

### Backend won't start

1. Check logs: `docker compose logs backend`
2. Verify `.env` file exists in `backend/`
3. Ensure port 8000 is not in use

### Frontend can't reach backend

1. Check CORS settings in `backend/.env`
2. Verify `NEXT_PUBLIC_BACKEND_URL` is correct

### Neo4j fails to start (full mode)

1. Ensure sufficient memory (2GB+)
2. Check Neo4j logs: `docker compose logs neo4j`

### Reset everything

```bash
# Stop all containers
docker compose -f infra/docker/compose/compose.full.yml down -v

# Remove all volumes (data will be lost)
docker volume prune
```
