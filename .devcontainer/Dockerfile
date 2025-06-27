FROM mcr.microsoft.com/devcontainers/python:3.12-bullseye

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    gnupg \
    libffi-dev \
    libsecret-1-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install UV package manager
# Install UV package manager with integrity verification
RUN curl -LsSf -o /tmp/uv-x86_64-unknown-linux-gnu.tar.gz https://github.com/astral-sh/uv/releases/download/0.7.15/uv-x86_64-unknown-linux-gnu.tar.gz \
    && echo "b1dc0892749e93382decbd894755be0ba1535587f0bb8333572b072d1b0f652a  /tmp/uv-x86_64-unknown-linux-gnu.tar.gz" > /tmp/uv-x86_64-unknown-linux-gnu.tar.gz.sha256 \
    && sha256sum -c /tmp/uv-x86_64-unknown-linux-gnu.tar.gz.sha256 \
    && tar -xzf /tmp/uv-x86_64-unknown-linux-gnu.tar.gz -C /usr/local/bin uv \
    && chmod +x /usr/local/bin/uv \
    && rm /tmp/uv-x86_64-unknown-linux-gnu.tar.gz /tmp/uv-x86_64-unknown-linux-gnu.tar.gz.sha256

# Create non-root user
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
    && echo >> /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Switch to non-root user
USER $USERNAME

# Set working directory
WORKDIR /workspaces/perihelion-auth-manager
