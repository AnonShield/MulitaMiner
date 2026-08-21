"""Preflight check for the local-model path: is Ollama up and are the models pulled?

Usage: python claims/check_ollama.py [model ...]
Exits 0 when everything needed is present, 1 otherwise.
"""
import json
import sys
import urllib.error
import urllib.request

DEFAULT_ENDPOINT = "http://localhost:11434"


def config_endpoint(llm_name: str) -> str:
    """Read the endpoint from the LLM config, falling back to the default."""
    try:
        with open(f"src/configs/llms/{llm_name}.json", encoding="utf-8") as f:
            return json.load(f).get("endpoint", DEFAULT_ENDPOINT).rstrip("/")
    except Exception:
        return DEFAULT_ENDPOINT


def config_model(llm_name: str) -> str | None:
    try:
        with open(f"src/configs/llms/{llm_name}.json", encoding="utf-8") as f:
            return json.load(f).get("model")
    except Exception:
        return None


def pull(endpoint: str, model: str) -> bool:
    """Ask the server to pull a model. Blocks until it finishes."""
    print(f"  pulling {model} ...")
    body = json.dumps({"model": model, "stream": False}).encode()
    req = urllib.request.Request(
        f"{endpoint}/api/pull", data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=3600) as r:
            return json.load(r).get("status") == "success"
    except Exception as e:
        print(f"  {type(e).__name__}: {e}")
        return False


def installed_models(endpoint: str) -> list[str] | None:
    try:
        with urllib.request.urlopen(f"{endpoint}/api/tags", timeout=10) as r:
            return [m["name"] for m in json.load(r).get("models", [])]
    except Exception:
        return None


def main() -> int:
    wanted_cfgs = sys.argv[1:] or ["ministral3"]
    endpoint = config_endpoint(wanted_cfgs[0])

    print(f"[CHECK] Ollama endpoint: {endpoint}")
    have = installed_models(endpoint)

    if have is None:
        print("[CHECK] FAILED: could not reach Ollama at that endpoint.")
        print()
        print("  Start it with Docker:")
        print("    docker run -d --gpus=all -v ollama:/root/.ollama \\")
        print("      -p 127.0.0.1:11434:11434 --name ollama ollama/ollama:0.30.0")
        print()
        print("  or install it natively from https://ollama.com/download")
        return 1

    print(f"[CHECK] Ollama is up, {len(have)} model(s) installed.")

    missing = []
    for cfg in wanted_cfgs:
        model = config_model(cfg)
        if model is None:
            print(f"[CHECK] WARNING: no config found for '{cfg}'")
            continue
        # Ollama reports 'name:tag'; a bare 'name' means the 'latest' tag
        found = any(m == model or m.split(":")[0] == model.split(":")[0] for m in have)
        print(f"  {'OK  ' if found else 'MISS'} {cfg:16} -> {model}")
        if not found:
            missing.append(model)

    if missing:
        print()
        print("[CHECK] Pulling the missing model(s), this may take a few minutes ...")
        for m in missing:
            if not pull(endpoint, m):
                print(f"[CHECK] FAILED: could not pull {m}. Pull it manually with:")
                print(f"    ollama pull {m}")
                return 1
        print("[CHECK] Done.")

    print("[CHECK] All required models are available.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
