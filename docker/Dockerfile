# Velora — container image for authorized security assessment.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VELORA_DATA_DIR=/data \
    VELORA_CONFIG_DIR=/config

WORKDIR /app

# Install build/runtime deps first for layer caching.
COPY pyproject.toml README.md LICENSE ./
COPY velora ./velora
RUN pip install --no-cache-dir . && \
    # Run as a non-root user (never run the web app as root).
    useradd --system --create-home --home-dir /home/velora velora && \
    mkdir -p /data /config && chown -R velora:velora /data /config /app

USER velora
EXPOSE 8787

# Default: launch the dashboard bound to all interfaces *inside the container*
# (map to 127.0.0.1 on the host in compose for a safe default).
CMD ["velora", "dashboard", "--host", "0.0.0.0", "--port", "8787"]
