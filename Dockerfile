# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /pdf_reader_tenableWAS

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory
RUN mkdir -p /pdf_reader_tenableWAS/output

# Set default command
ENTRYPOINT ["python", "main.py"]