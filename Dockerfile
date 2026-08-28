FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/
COPY run.py ./

# Install package
RUN pip install --no-cache-dir .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app

USER app

# Cloud Run uses PORT env variable (default 8080, but we prefer 8000)
ENV PORT=8000
# The container itself must bind 0.0.0.0 to be reachable from outside the
# container (Cloud Run, docker-compose port publish, etc). Host-level
# exposure is controlled by the caller: docker-compose.yml publishes this
# to 127.0.0.1 by default. If this container is ever published on a
# non-loopback address or a public host, MCP_AUTH_TOKEN MUST be set, since
# host_origin_protection is not usable with a bare 0.0.0.0 bind (it would
# need an allowed_hosts list, which we don't have here).
ENV HOST=0.0.0.0
ENV MCP_AUTH_TOKEN=""
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Run in HTTP/Streamable mode by default (for Cloud Run)
# Exec form + "exec" in the wrapper so python is PID 1 and receives SIGTERM
# directly for graceful shutdown (a shell-form CMD leaves sh as PID 1 and
# swallows the signal).
CMD ["sh", "-c", "exec python run.py --http --port ${PORT}"]
