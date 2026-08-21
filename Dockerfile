FROM python:3.11-slim

WORKDIR /app

# CPU-only torch: the default PyPI build pulls the CUDA stack (~2GB) that
# BERTScore never uses here.
ENV PIP_EXTRA_INDEX_URL=https://download.pytorch.org/whl/cpu \
    PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Bake the BERTScore model into the image so the metric phase of the claims
# needs no network. Same model and settings as metrics/scorers/bertscore.py.
RUN python -c "from bert_score import BERTScorer; BERTScorer(model_type='distilbert-base-uncased', lang='en', device='cpu', rescale_with_baseline=True)"

COPY . .

# A Windows build context can carry CRLF into the image; the claim scripts run under bash.
RUN sed -i 's/\r$//' claims/*.sh

CMD ["python", "main.py", "--help"]
