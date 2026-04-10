# Setting Up Local LLMs with Ollama

This guide explains how to use local LLMs with MulitaMiner through Ollama.

## Prerequisites

- 8GB RAM minimum (for 7B parameter models)
- 20GB free disk space (for base Ollama + models)
- Windows, macOS, or Linux

## Step 1: Install Ollama

### Windows

- Download from https://ollama.com/download/windows
- Run the installer
- Ollama will run as a service automatically

### macOS

```bash
brew install ollama
```

### Linux

```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

## Step 2: Start Ollama

### Windows & macOS

Ollama runs as a background service automatically.

Verify it's running:

```bash
curl http://localhost:11434/api/tags
```

### Linux

```bash
ollama serve
```

## Step 3: Download a Model

Choose one of the recommended models:

### Mistral 7B (Recommended for starting)

```bash
ollama run mistral
```

- Download: ~4GB
- RAM Usage: ~8GB
- Speed: Fast (5-10 seconds per prompt)
- Quality: Good (85% accuracy)

### DeepSeek Coder 7B

```bash
ollama run deepseek-coder:7b
```

- Download: ~8GB
- RAM Usage: ~16GB
- Speed: Medium (10-15 seconds)
- Quality: Very good (92% accuracy)

### Llama 2 7B

```bash
ollama run llama2
```

- Download: ~4GB
- RAM Usage: ~8GB
- Speed: Fast
- Quality: Good

### Other Models

Browse available models at https://ollama.ai/library

Common commands:

```bash
ollama list          # Show installed models
ollama pull mistral  # Download without running
ollama rm mistral    # Remove a model
```

## Step 4: Use with MulitaMiner

### Option A: Using Mistral (Recommended)

```bash
python main.py \
  --input scan_report.pdf \
  --scanner openvas \
  --llm ollama-local
```

### Option B: Using DeepSeek

```bash
python main.py \
  --input scan_report.pdf \
  --scanner openvas \
  --llm ollama-deepseek
```

### Option C: Using Your Own Configuration

Create a new JSON file in `src/configs/llms/`:

```json
{
  "type": "ollama",
  "model": "llama2",
  "endpoint": "http://localhost:11434",
  "temperature": 0.0,
  "max_tokens": 4096,
  "max_chunk_size": 2800,
  "reserve_for_response": 1000,
  "tokenizer": {
    "type": "huggingface",
    "model": "meta-llama/Llama-2-7b-hf"
  }
}
```

Then use with:

```bash
python main.py --input scan.pdf --llm llama2
```

## Troubleshooting

### Connection Error: "Connection refused"

**Problem:** Ollama is not running

**Solution:**

```bash
# Windows: Ensure Ollama service is running
# macOS: Restart Ollama service
# Linux: Run: ollama serve
```

### Model Not Found Error

**Problem:** Model hasn't been downloaded yet

**Solution:**

```bash
ollama run mistral
# Wait for download to complete (~5-10 minutes)
```

### Out of Memory Error

**Problem:** Model requires more RAM than available

**Solutions:**

- Use a smaller model (7B instead of 13B)
- Close other applications
- Increase system page file/swap space

### Slow Responses

**Problem:** Model is running slowly

**Possible causes:**

- CPU-only inference (no GPU support)
- Insufficient RAM for model
- System doing other heavy tasks

**Solutions:**

- Close unnecessary applications
- Use a faster model
- Consider GPU support (requires NVIDIA/AMD GPU + setup)

## Performance Expectations

| Model        | Size | Speed  | Quality   | RAM  |
| ------------ | ---- | ------ | --------- | ---- |
| Mistral 7B   | 4GB  | 5-10s  | Good      | 8GB  |
| DeepSeek 7B  | 8GB  | 10-15s | Very Good | 16GB |
| Llama2 7B    | 4GB  | 5-10s  | Good      | 8GB  |
| DeepSeek 13B | 8GB  | 20-30s | Excellent | 20GB |

## Advanced: Custom Model Configuration

To add a model not in the default list:

1. Install the model with Ollama:

   ```bash
   ollama run neural-chat
   ```

2. Create configuration in `src/configs/llms/custom.json`:

   ```json
   {
     "type": "ollama",
     "model": "neural-chat",
     "endpoint": "http://localhost:11434",
     "temperature": 0.0,
     "max_tokens": 4096,
     "max_chunk_size": 2800,
     "reserve_for_response": 1000,
     "tokenizer": {
       "type": "huggingface",
       "model": "Intel/neural-chat-7b-v3-1"
     }
   }
   ```

3. Use it:
   ```bash
   python main.py --input scan.pdf --llm custom
   ```

## Differences from OpenAI API

| Aspect   | OpenAI (API)        | Ollama (Local)    |
| -------- | ------------------- | ----------------- |
| Internet | Required            | Not required      |
| Cost     | Pay per token       | Free              |
| Speed    | Depends on internet | Instant (local)   |
| Privacy  | Sent to OpenAI      | Stays on machine  |
| Models   | Limited to OpenAI   | Many open models  |
| Setup    | API key             | One-time download |

## Getting Help

If you encounter issues:

1. Check Ollama logs:

   ```bash
   # Linux: journalctl -u ollama
   # Windows: Check Event Viewer
   ```

2. Verify model is loaded:

   ```bash
   curl http://localhost:11434/api/tags
   ```

3. Test Ollama directly:

   ```bash
   curl -X POST http://localhost:11434/api/chat -d '{
     "model": "mistral",
     "messages": [{"role": "user", "content": "hello"}]
   }'
   ```

4. See Ollama documentation: https://github.com/jmorganca/ollama
