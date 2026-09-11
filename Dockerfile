# syntax=docker/dockerfile:1
# ------------------------------------------------------------------------------
# Stage 1: Build stage
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends     build-essential     && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY setu/ ./setu/
COPY bpf/ ./bpf/

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip wheel --no-deps -w /build/dist .

# ------------------------------------------------------------------------------
# Stage 2: Hardened Runtime
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL maintainer="Kanak Prabhakar <kanakprabhakar72@gmail.com>" \
      description="SETU — Kernel eBPF & Local LLM Bridge Daemon" \
      version="0.1.0"

# Create non-root system user and group with explicit UID/GID
RUN groupadd -g 10001 setu && \
    useradd -u 10001 -g setu -m -s /usr/sbin/nologin setu

WORKDIR /app

# Install compiled wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Switch to unprivileged user
USER 10001:10001

# Healthcheck validating wire contracts, struct alignments, and policy table
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD setu health || exit 1

ENTRYPOINT ["setu"]
CMD ["health"]
