# Running MulitaMiner in Docker

One `Dockerfile` builds **two images** (pick with `--target`):

| Image | What's in it | For |
|-------|--------------|-----|
| `extraction` | extraction runtime only — lean, no torch/metrics | the common user: PDF → structured JSON |
| `full` | extraction **+** experiments, metrics, charts, Marker | research / benchmarking |

Keys are never baked into the image; inputs and outputs are bind-mounted at run
time.

---

## 1. Build

```bash
# Lean, common-user image (no metrics/ML stack):
docker build --target extraction -t mulitaminer:extraction .

# Research image (everything). Torch defaults to CPU — portable and far
# smaller. For a GPU box, point torch at the matching CUDA wheel index:
docker build --target full -t mulitaminer:full .
docker build --target full -t mulitaminer:full \
  --build-arg TORCH_INDEX=https://download.pytorch.org/whl/cu128 .
```

The `extraction` image resolves ~60 packages; `full` ~115 (torch + CUDA libs are
the bulk of the difference).

## 2. Run an extraction

```bash
docker run --rm \
  --env-file .env \
  -v "$PWD/input:/app/input" \
  -v "$PWD/outputs:/app/outputs" \
  mulitaminer:extraction --input /app/input/report.pdf --scanner openvas --llm gpt4
```

- `--input` points at a PDF **inside the container** — so mount the host folder
  that holds it (`-v "$PWD/input:/app/input"`).
- Results are written under `/app/outputs`; mount it so they land on the host.
- `--rm` discards the container after the run (the output is on the mounted
  volume, not in the container).

The `full` image has `ENTRYPOINT python`, so it runs any script:

```bash
docker run --rm --env-file .env -v "$PWD/outputs:/app/outputs" \
  mulitaminer:full tools/run_experiments.py ...
```

## 3. API keys

Keys are **environment variables**, referenced by each LLM config as
`${VAR_NAME}` and substituted when the config loads. The variable name must
match the one the chosen LLM's JSON uses — `gpt4.json` references
`${API_KEY_GPT4}`, so the variable is `API_KEY_GPT4`.

Pass them at run time (never in the image):

```bash
# A — a host .env file (API_KEY_GPT4=sk-... inside it):
docker run --rm --env-file .env ... --llm gpt4

# B — individual variables:
docker run --rm -e API_KEY_GPT4=sk-... ... --llm gpt4
```

`.env` is in `.dockerignore`, so it never enters the build context or the image.
See [.env.example](../.env.example) for the variable names the shipped configs
use.

## 4. Custom LLM / scanner configs (no rebuild)

The built-in configs live inside the image. To **add or override** a config
without rebuilding, mount a directory and point `MULITA_CONFIG_DIR` at it. The
loader checks that directory first and falls back to the packaged configs, so
your files shadow or extend the built-ins.

The directory mirrors the package layout — `llms/` and `scanners/` subfolders:

```
myconfigs/
├── llms/
│   └── myllm.json
└── scanners/
    └── myscanner.json
```

`myconfigs/llms/myllm.json`:

```json
{
  "api_key": "${API_KEY_MYLLM}",
  "endpoint": "https://api.openai.com/v1",
  "model": "gpt-4o-mini-2024-07-18",
  "temperature": 0.0,
  "max_completion_tokens": 14500,
  "max_chunk_size": 14000,
  "reserve_for_response": 3500,
  "tokenizer": { "type": "tiktoken", "model": "cl100k_base" }
}
```

Run it:

```bash
docker run --rm \
  --env-file .env -e API_KEY_MYLLM=sk-... \
  -e MULITA_CONFIG_DIR=/configs \
  -v "$PWD/myconfigs:/configs" \
  -v "$PWD/input:/app/input" -v "$PWD/outputs:/app/outputs" \
  mulitaminer:extraction --input /app/input/report.pdf --scanner openvas --llm myllm
```

**Custom scanner with its own prompt:** a scanner JSON's `prompt_template` may be
an **absolute path** — mount the prompt and reference it directly, e.g.
`"prompt_template": "/configs/prompts/myprompt.txt"` with
`-v "$PWD/myconfigs:/configs"`.

## 5. Local LLM (Ollama) instead of a cloud API

Local models need no key, but the container must reach the Ollama running on the
host. Point the LLM config's `endpoint` at `http://host.docker.internal:11434`
and add the host gateway:

```bash
docker run --rm --add-host=host.docker.internal:host-gateway \
  -v "$PWD/input:/app/input" -v "$PWD/outputs:/app/outputs" \
  mulitaminer:extraction --input /app/input/report.pdf --scanner openvas --llm my-ollama
```

(On Linux you can also use `--network host` and `http://localhost:11434`.)

## Gotchas

- **The `extraction` image is extraction-only.** Passing `--metrics ...` there
  fails — the metrics stack isn't installed. Use the `full` image for evaluation.
- **Output permissions:** the container runs as root, so files written to the
  mounted `outputs/` are root-owned on the host. `chown` them if needed, or
  adjust to your setup.
- **Keep the build context lean:** `.dockerignore` excludes `outputs/`, `.venv/`,
  `.git/`, `.env`, etc. Don't remove those entries.
