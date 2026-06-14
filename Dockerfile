FROM python:3.12-slim-bookworm

LABEL maintainer="AgentGuard Team"
LABEL description="AgentGuard-CLI - Lightweight AI Agent Skill Security Scanner"

WORKDIR /app

# Copy source
COPY pyproject.toml ./
COPY src/ ./src/

# Install
RUN pip install --no-cache-dir -e .

# Set working directory for scans
WORKDIR /scan

ENTRYPOINT ["agentguard"]
CMD ["--help"]
