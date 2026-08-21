FROM python:3.11-slim

WORKDIR /app

# CPU-only torch: the default PyPI build pulls the CUDA stack (~2GB) that
# BERTScore never uses here.
ENV PIP_EXTRA_INDEX_URL=https://download.pytorch.org/whl/cpu \
    PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# A Windows build context can carry CRLF into the image; the claim scripts run under bash.
RUN sed -i 's/\r$//' claims/*.sh

CMD ["python", "main.py", "--help"]
