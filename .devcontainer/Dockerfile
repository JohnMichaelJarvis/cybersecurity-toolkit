FROM python:3.12-slim

# Noninteractive apt and sensible defaults for Python containers
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system packages including clipboard backends (xclip/xsel/wl-clipboard)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    xclip xsel wl-clipboard git curl ca-certificates build-essential && \
    rm -rf /var/lib/apt/lists/*

# Create workspace dir and switch to it
WORKDIR /workspaces/cybersecurity-toolkit

# Copy requirements.txt first to leverage Docker cache if present
# If you don't have requirements.txt, the conditional install below will be a no-op.
COPY requirements.txt /workspaces/cybersecurity-toolkit/

# Install Python dependencies if requirements.txt exists
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# Copy the rest of the project
COPY . /workspaces/cybersecurity-toolkit

# Create an unprivileged user for interactive use (optional but recommended)
RUN useradd -m -s /bin/bash devuser || true
USER devuser
ENV PATH="/home/devuser/.local/bin:${PATH}"

# Default command
CMD ["bash"]
