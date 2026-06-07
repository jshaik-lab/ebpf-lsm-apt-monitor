# ── SENTINEL Production Dockerfile ─────────────────────────────────────────────
# Multi-stage build: compiles the eBPF object then assembles a slim Python image.
# Supports linux/amd64 and linux/arm64 (Mac M-series).
#
# Build:
#   docker build -f docker/Dockerfile -t sentinel .
#
# Run (simulation mode, no root):
#   docker run --rm -p 8080:8080 -p 9090:9090 sentinel
#
# Run (live eBPF inside Docker VM, requires privileged):
#   docker run --rm --privileged --pid=host \
#     -v /sys/kernel/debug:/sys/kernel/debug \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v /lib/modules:/lib/modules:ro \
#     -p 8080:8080 -p 9090:9090 \
#     sentinel --config /sentinel/config/sentinel.ebpf.yaml

# ── Stage 1: eBPF compiler ──────────────────────────────────────────────────────
FROM ubuntu:22.04 AS bpf-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/bpf/sentinel.c .

# Detect arch and compile for the correct BPF target
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then BPF_ARCH="arm64"; else BPF_ARCH="x86_64"; fi && \
    clang -O2 -target bpf \
        -D__TARGET_ARCH_${BPF_ARCH} \
        -I/usr/include/bpf \
        -g \
        -c sentinel.c -o sentinel.bpf.o 2>/dev/null || \
    echo "Note: eBPF pre-compilation skipped (headers mismatch at build time)" && \
    touch sentinel.bpf.o   # ensure file exists even on failure

# ── Stage 2: Python runtime ─────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="SENTINEL Research"
LABEL description="SENTINEL production — eBPF + LLM zero-trust anomaly detection"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/sentinel/src/python

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        curl \
        # BCC for live eBPF mode
        python3-bpfcc \
        bpfcc-tools \
        libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sentinel

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/python/ /sentinel/src/python/
COPY config/     /sentinel/config/

# Copy compiled eBPF object
COPY --from=bpf-builder /build/sentinel.bpf.o /sentinel/src/bpf/sentinel.bpf.o
COPY src/bpf/sentinel.c /sentinel/src/bpf/

# Create log directory
RUN mkdir -p /var/log/sentinel

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 9090

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--config", "/sentinel/config/sentinel.yaml"]
