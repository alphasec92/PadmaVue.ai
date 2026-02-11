# ===========================================
# PadmaVue.ai Backend Dockerfile
# Security-hardened Python application
# ===========================================

# Build stage
FROM python:3.11-slim as builder

# Set build-time variables
ARG DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# ===========================================
# Production stage
# ===========================================
FROM python:3.11-slim as production

# Security: Create non-root user
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /var/cache/apt/archives/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create app directory with proper ownership (needed for multiprocessing chdir)
RUN mkdir -p /app && chown appuser:appgroup /app && chmod 755 /app

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=appuser:appgroup . .

# Ensure all files are owned by appuser (explicit ownership)
RUN chown -R appuser:appgroup /app

# Create uploads directory with proper permissions
RUN mkdir -p /app/uploads && chown appuser:appgroup /app/uploads

# Security: Set proper permissions
# u+rwX gives user read/write/execute (X only applies execute to directories)
# go-rwx removes all group/other permissions
RUN chmod -R u+rwX,go-rwx /app \
    && chmod 700 /app/uploads

# Security: Remove unnecessary files
RUN rm -rf /app/__pycache__ /app/.pytest_cache /app/.git 2>/dev/null || true

# Switch to non-root user
USER appuser

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application with security settings
CMD ["uvicorn", "app.main:app", \
    "--host", "0.0.0.0", \
    "--port", "8000", \
    "--workers", "2", \
    "--limit-concurrency", "100", \
    "--limit-max-requests", "10000", \
    "--timeout-keep-alive", "5"]
