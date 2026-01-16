# Environment Templates

This folder contains environment variable templates for the SecurityReview.ai application.

## Setup Instructions

### Backend Configuration

Copy the backend template to the backend folder:

```bash
cp env-templates/backend.env backend/.env
```

Edit `backend/.env` and configure your settings:
- Set `LLM_PROVIDER` to `mock` for offline development
- Add API keys if using OpenAI or Anthropic

### Frontend Configuration

Copy the frontend template to the frontend folder:

```bash
cp env-templates/frontend.env frontend/.env.local
```

The default settings should work for local development.

## Quick Setup

You can use the setup script to automatically copy templates:

```bash
./scripts/setup-local.sh
```

This will:
1. Create environment files from templates
2. Start all services with Docker Compose
3. Display access URLs for all services


