# =================================================================
# MulitaMiner - Vulnerability Extraction Tool
# Dockerfile for containerized deployment
# =================================================================

FROM python:3.11-slim-bullseye

# Metadata
LABEL maintainer="MulitaMiner Team"
LABEL description="Vulnerability Extraction from Security Reports using LLMs"
LABEL version="1.0.0"

# Environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        libjpeg-dev \
        libpng-dev \
        libfreetype6-dev \
        pkg-config \
        poppler-utils \
        tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Create app directory and user
RUN useradd --create-home --shell /bin/bash mulitaminer
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/data /app/results /app/jsons /app/pdfs /app/metrics \
    && chown -R mulitaminer:mulitaminer /app

# Switch to non-root user
USER mulitaminer

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Expose port if needed (for future web interface)
EXPOSE 8000

# Default command
CMD ["python", "main.py", "--help"]