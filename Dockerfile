# syntax=docker/dockerfile:1
#
# Two images from one file (pick with --target):
#
#   extraction  — common-user image: PDF -> structured JSON. Lean (no torch /
#                 metrics / Marker). This is the "appliance" build.
#       docker build --target extraction -t mulitaminer:extraction .
#
#   full        — research image: extraction + experiments + metrics + charts +
#                 Marker backend. Torch defaults to CPU (portable, smaller);
#                 pass --build-arg TORCH_INDEX=.../cu128 for a GPU build.
#       docker build --target full -t mulitaminer:full .
#
# Run (keys come in at runtime — never baked into the image):
#   docker run --rm --env-file .env \
#     -v "$PWD/input:/app/input" -v "$PWD/outputs:/app/outputs" \
#     mulitaminer:extraction --input /app/input/report.pdf --scanner openvas --llm gpt4

# ── base: shared interpreter + uv + package source ──────────────────────────
FROM python:3.11-slim AS base

# uv: fast, deterministic installs (https://docs.astral.sh/uv/).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_SYSTEM_PYTHON=1 \
    UV_COMPILE_BYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Package metadata + source first so the (slow) dependency layers stay cached
# when only the top-level scripts (main.py / tools) change.
COPY pyproject.toml ./
COPY src/ ./src/

# ── extraction: common-user image (no metrics / ML stack) ───────────────────
FROM base AS extraction
# Editable install keeps the JSON/prompt configs under src/ resolvable at
# runtime. Core deps are pure wheels, so no compiler/git needed here.
RUN uv pip install -e .
COPY main.py ./
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

# ── full: research image (extraction + metrics + charts + Marker) ───────────
FROM base AS full
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
# CPU torch by default: portable and far smaller than the CUDA wheel. For a GPU
# box: --build-arg TORCH_INDEX=https://download.pytorch.org/whl/cu128
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu
RUN uv pip install torch==2.11.0 --index-url ${TORCH_INDEX}
RUN uv pip install -e ".[full]"
COPY main.py ./
COPY tools/ ./tools/
COPY resources/ ./resources/
ENTRYPOINT ["python"]
CMD ["main.py", "--help"]
