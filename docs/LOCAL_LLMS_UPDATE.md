# Atualização: Suporte a LLMs Locais no MulitaMiner

**Data:** 7 de abril de 2026  
**Status:** ✅ Implementado e testado

> **📖 Documentação Relacionada:**
>
> - Ver [ARCHITECTURE.md](ARCHITECTURE.md) → seção `model_management/` para visão geral da arquitetura
> - Ver [CONFIG.md](CONFIG.md) → seção `Local LLMs (Ollama)` para guia de configuração prático
> - Ver [SETUP_OLLAMA.md](SETUP_OLLAMA.md) para setup detalhado e escalabilidade

---

## Sumário Executivo

O MulitaMiner agora suporta **quatro tipos de provedores de LLM**:

| Provider      | Tipo      | Onde Roda              | Requer Credenciais | Melhor Para          |
| ------------- | --------- | ---------------------- | ------------------ | -------------------- |
| `openai`      | API       | Remoto (OpenAI)        | ✅ API Key         | Máxima qualidade     |
| `ollama`      | Local     | Seu computador (11434) | ❌ Não             | Flexibilidade        |
| `llm_studio`  | Local     | Seu computador (1234)  | ❌ Não             | Granite models ⚡    |
| `huggingface` | API/Local | Remoto ou Local        | ✅ Opcional        | Modelos customizados |

---

## O que Mudou

### 1. Criação do Módulo `src/model_management/`

Novo módulo centralizado para gerenciar LLMs com **Provider Pattern**:

```
src/model_management/
├── __init__.py
├── config_loader.py       # Carrega configs JSON com auto-detecção
├── llm_factory.py         # Factory que rota para provider correto
├── validation.py          # Valida respostas com tokenizers abstratos
├── tokenizer_utils.py     # Tokenizers compartilhados
├── llm_processing.py      # Pipeline de inferência
├── prompts.py             # Templates de prompts
└── providers/
    ├── __init__.py
    ├── base_provider.py             # Interface abstrata
    ├── openai_provider.py           # ChatOpenAI (remoto)
    ├── ollama_provider.py           # ChatOllama (local, port 11434)
    ├── llm_studio_provider.py       # LLM Studio (local, port 1234 - Granite)
    └── huggingface_provider.py      # HuggingFace (remoto ou local)
```

### 2. Arquitetura de Provedores

Cada provedor implementa a mesma interface (`BaseLLMProvider`):

```python
class BaseLLMProvider(ABC):
    def invoke(self, prompt: str) -> str: ...
    def get_model_name(self) -> str: ...
```

**Benefícios:**

- Código agnóstico ao provider (mesma interface)
- Fácil adicionar novos providers
- Tokenizers abstratos (cada provider usa seu próprio)

### 3. Atributo `provider` em JSONs

Agora os JSONs declaram qual provider usar (antes era implícito via `type`):

```json
{
  "provider": "ollama",
  "model": "mistral",
  "endpoint": "http://localhost:11434"
}
```

**Ou auto-detectado** se não especificado:

```json
{
  "endpoint": "https://api.openai.com/v1" // → auto-detecta como "openai"
}
```

### 4. Detecção Automática de Provider

`config_loader.py` detecta automaticamente se um JSON é:

- **API remota:** Se tem `endpoint` contendo domínios conhecidos (openai.com, anthropic.com, etc.)
- **Local (Ollama):** Se tem `localhost`, `127.0.0.1`, ou porta `11434`
- **Local (LLM Studio):** Se tem `localhost`, `127.0.0.1`, ou porta `1234`
- **Padrão:** OpenAI (backward compatibility)

```python
# Em config_loader.py
if "provider" not in config:
    endpoint = config.get("endpoint", "").lower()

    if "localhost" in endpoint or "11434" in endpoint:
        config["provider"] = "ollama"
    elif "localhost" in endpoint and "1234" in endpoint:
        config["provider"] = "llm_studio"
    elif "openai" in endpoint:
        config["provider"] = "openai"
    else:
        config["provider"] = "openai"  # default
```

---

## Como Funciona o Pipeline Completo

### 1️⃣ Usuário Executa

```bash
python main.py --input scan.pdf --llm ollama-local
```

### 2️⃣ Sistema Carrega Configuação

`config_loader.load_llm("ollama-local")`:

- Procura por `src/configs/llms/ollama-local.json`
- Substitui variáveis de ambiente (`${OLLAMA_HOST}`, etc.)
- **Auto-detecta provider** se não especificado
- Retorna dict com config resolvida

### 3️⃣ Factory Cria Provider Correto

`llm_factory.init_llm(config)`:

```python
provider_type = config.get("provider", "openai")

if provider_type == "openai":
    return OpenAIProvider(config)         # ChatOpenAI
elif provider_type == "ollama":
    return OllamaProvider(config)         # ChatOllama (local)
elif provider_type == "huggingface":
    # Verifica se tem api_key
    if config.get("api_key"):
        return HuggingFaceRemoteProvider()  # HF Inference API
    else:
        return HuggingFaceLocalProvider()   # transformers local
```

### 4️⃣ Provider Inicializa LLM

Exemplo **OllamaProvider**:

```python
class OllamaProvider(BaseLLMProvider):
    def __init__(self, config):
        self.llm = ChatOllama(
            model=config["model"],           # "mistral"
            base_url=config["endpoint"],     # "http://localhost:11434"
            temperature=config["temperature"]
        )

    def invoke(self, prompt: str) -> str:
        return self.llm.invoke(prompt).content  # retorna string

    def get_model_name(self) -> str:
        return self.model
```

### 5️⃣ Pipeline Processa Documento

Em `main.py`:

1. Carrega LLM: `llm = init_llm(llm_config)`
2. Divide PDF em chunks: `chunks = get_token_based_chunks(doc, llm, config)`
3. Para cada chunk, processa:
   ```python
   response = llm.invoke(prompt)  # mesmo que provider
   validate_json_and_tokens(response, chunk, tokenizer=get_tokenizer(...))
   ```

**Key Points:**

- `invoke()` sempre retorna **string** (abstração)
- Tokenizer é **abstrato** (cada provider usa seu):
  - OpenAI → `tiktoken` (cl100k_base)
  - Ollama → `huggingface` (mistralai/Mistral-7B-Instruct-v0.2)
  - HF Local → `huggingface` (baseado no modelo)

3️⃣ Extrai vulnerabilidades:

```python
vulns = extract_vulns_from_blocks(response, validator_fn)
```

### 6️⃣ Salva Resultados

Mesmo fluxo que antes, compatível 100%:

- JSON
- CSV
- XLSX

---

## Configurations Disponíveis

### ✅ OpenAI (API) - `gpt4.json`

```json
{
  "api_key": "${API_KEY_GPT4}",
  "endpoint": "https://api.openai.com/v1",
  "model": "gpt-4o-mini-2024-07-18",
  "temperature": 0.0,
  "max_completion_tokens": 12000,
  "max_chunk_size": 10000,
  "reserve_for_response": 2000,
  "tokenizer": {
    "type": "tiktoken",
    "model": "cl100k_base"
  }
}
```

**Uso:**

```bash
python main.py --input scan.pdf --llm gpt4
```

### ✅ Ollama Local (Mistral) - `ollama-local.json`

```json
{
  "provider": "ollama",
  "model": "mistral",
  "endpoint": "http://localhost:11434",
  "temperature": 0.0,
  "max_tokens": 4096,
  "max_chunk_size": 2800,
  "reserve_for_response": 1000,
  "tokenizer": {
    "type": "huggingface",
    "model": "mistralai/Mistral-7B-Instruct-v0.2"
  }
}
```

**Setup Required:**

```bash
# 1. Instalar Ollama: https://ollama.ai
ollama pull mistral

# 2. Rodar Ollama em background
ollama serve

# 3. Em outro terminal
python main.py --input scan.pdf --llm ollama-local
```

### ✅ Ollama Local (DeepSeek) - `ollama-deepseek.json`

```json
{
  "provider": "ollama",
  "model": "deepseek-coder:7b",
  "endpoint": "http://localhost:11434",
  "temperature": 0.0,
  "max_tokens": 8000,
  "max_chunk_size": 3000,
  "reserve_for_response": 1500,
  "tokenizer": {
    "type": "huggingface",
    "model": "deepseek-ai/deepseek-coder-7b-instruct-v1.5"
  }
}
```

**Setup:**

```bash
ollama pull deepseek-coder:7b
python main.py --input scan.pdf --llm ollama-deepseek
```

### ✅ LLM Studio Local (Granite 4 Tiny) - `granite4.json` **[RECOMENDADO]**

**O melhor custo-benefício testado localmente** - Granite 4 Tiny oferece excelente qualidade com footprint pequeno (4GB RAM).

```json
{
  "provider": "llm_studio",
  "model": "ibm/granite-4-h-tiny",
  "endpoint": "http://localhost:1234/v1",
  "temperature": 0.0,
  "max_tokens": 1500,
  "max_chunk_size": 4000,
  "reserve_for_response": 600,
  "timeout": 180,
  "tokenizer": {
    "type": "huggingface",
    "model": "ibm-granite/granite-4.0-h-tiny"
  }
}
```

**Setup:**

1. Download LLM Studio: https://github.com/mlc-ai/llm-studio/releases
2. Extract e abra a pasta
3. Execute `./LM Studio` (UI vai abrir em http://localhost:3000)
4. Na aba "Server" → Load Model: select `ibm/granite-4-h-tiny`
5. Aguarde até completar (~5-10 min primeira vez)
6. Servidor estará em http://localhost:1234

**Uso:**

```bash
# LLM Studio já está rodando em background
python main.py --input scan.pdf --llm granite4
```

**Por que Granite 4 Tiny é melhor que Ollama:**

- ⚡ Inferência mais rápida (LLM Studio é otimizado)
- 📦 Menos RAM (~4GB vs 8GB do Mistral)
- 🎯 Qualidade superior em segurança (treinado em datasets de segurança)
- 🔧 Interface GUI para gerenciar modelos

### ✅ LLM Studio Local (Granite 3.2) - `granite32.json`

```json
{
  "provider": "llm_studio",
  "model": "ibm/granite-3.2-8b-instruct",
  "endpoint": "http://localhost:1234/v1",
  "temperature": 0.0,
  "max_tokens": 3000,
  "max_chunk_size": 2500,
  "reserve_for_response": 1200,
  "timeout": 180,
  "tokenizer": {
    "type": "huggingface",
    "model": "ibm-granite/granite-3.2-8b-instruct"
  }
}
```

**Uso:**

```bash
# No LLM Studio GUI, trocar modelo para ibm/granite-3.2-8b-instruct
python main.py --input scan.pdf --llm granite32
```

### ✅ HuggingFace Remoto (com API) - `huggingface-remote.json`

```json
{
  "provider": "huggingface",
  "api_key": "${HF_TOKEN}",
  "model": "mistralai/Mistral-7B-Instruct-v0.2",
  "temperature": 0.7,
  "max_length": 512,
  "tokenizer": {
    "type": "huggingface",
    "model": "mistralai/Mistral-7B-Instruct-v0.2"
  }
}
```

**Uso:**

```bash
export HF_TOKEN="seu_token_aqui"
python main.py --input scan.pdf --llm huggingface-remote
```

### ✅ HuggingFace Local (sem API) - `huggingface-local.json`

```json
{
  "provider": "huggingface",
  "model": "mistralai/Mistral-7B-Instruct-v0.2",
  "temperature": 0.7,
  "max_length": 512,
  "tokenizer": {
    "type": "huggingface",
    "model": "mistralai/Mistral-7B-Instruct-v0.2"
  }
}
```

**Setup:**

```bash
pip install transformers torch
python main.py --input scan.pdf --llm huggingface-local
```

**Nota:** Sem `api_key` → factory automaticamente usa `HuggingFaceLocalProvider` (transformers)

---

## Fluxo de Decisão da Factory

```
┌─────────────────────────────────────────────────────────────┐
│ User: --llm <name>                                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │ load_llm(<name>)             │
        │ • Load JSON                  │
        │ • Substitute env vars        │
        │ • Auto-detect provider       │
        └──────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │ provider = config.get(       │
        │   "provider", auto-detected) │
        └──────────────────────────────┘
                       │
        ┌──────────────┼──────────────┬──────────────┐
        │              │              │              │
        ▼              ▼              ▼              ▼
    "openai"       "ollama"    "huggingface"    otros?
        │              │              │              │
        ▼              ▼              ▼              ▼
    OpenAI      OllamaProvider   HAS api_key?   Custom
    Provider                          │      (dynamic import)
                                   ┌──┴──┐
                                   ▼     ▼
                                Remote  Local
                                (HF API) (transformers)
```

---

## Tokenizers Abstrato

Cada provider usa seu próprio tokenizer:

| Provider        | Tokenizer | Dependência    | Uso                                           |
| --------------- | --------- | -------------- | --------------------------------------------- |
| OpenAI          | tiktoken  | `tiktoken`     | `cl100k_base`                                 |
| Ollama Mistral  | HF        | `transformers` | `mistralai/Mistral-7B-Instruct-v0.2`          |
| Ollama DeepSeek | HF        | `transformers` | `deepseek-ai/deepseek-coder-7b-instruct-v1.5` |
| HF Remote       | HF        | `transformers` | Model-specific                                |
| HF Local        | HF        | `transformers` | Model-specific                                |

**Em `chunking.py`:**

```python
tokenizer = get_tokenizer(llm_config)
# tokenizer é qualquer coisa que tem: encode(text) → List[int]

chunks = get_token_based_chunks(doc, llm, llm_config)
# • Divide doc respeitando max_chunk_size
# • Usa tokenizer específico do provider

for chunk in chunks:
    response = llm.invoke(prompt)
    validate_json_and_tokens(
        response, chunk,
        max_tokens, prompt,
        tokenizer=tokenizer  # ← passa tokenizer
    )
```

---

## Backward Compatibility ✅

**Mudanças totalmente compatíveis com código existente:**

1. **CLI idêntica:**

   ```bash
   # Antes
   python main.py --input scan.pdf --llm gpt4

   # Depois (exato mesmo comando, mesmos resultados)
   python main.py --input scan.pdf --llm gpt4
   ```

2. **JSONs legados funcionam:**

   ```bash
   python main.py --input scan.pdf --llm gpt4  # ✅ Funciona
   ```

3. **Outputs idênticos:**
   - JSON vulnerabilities
   - CSV reports
   - XLSX files

All maintained with same structure.

---

## Adicionando Novo Provider Customizado

### Passo 1: Criar arquivo provider

```bash
# Criar: src/model_management/providers/anthropic_provider.py
```

```python
from .base_provider import BaseLLMProvider

class AnthropicProvider(BaseLLMProvider):
    def __init__(self, config: dict):
        from anthropic import Anthropic

        self.client = Anthropic(api_key=config.get("api_key"))
        self.model = config.get("model")
        self.temperature = config.get("temperature", 0.7)

    def invoke(self, prompt: str) -> str:
        message = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            temperature=self.temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def get_model_name(self) -> str:
        return self.model
```

### Passo 2: Adicionar ao factory (opcional, auto-discovery funciona)

Se quiser suporte explícito em `llm_factory.py`:

```python
elif provider_type == "anthropic":
    from .providers.anthropic_provider import AnthropicProvider
    return AnthropicProvider(llm_config)
```

### Passo 3: Criar config JSON

```bash
# Criar: src/configs/llms/anthropic.json
```

```json
{
  "provider": "anthropic",
  "api_key": "${ANTHROPIC_API_KEY}",
  "model": "claude-3-opus-20240229",
  "temperature": 0.7,
  "max_chunk_size": 8000,
  "reserve_for_response": 1000,
  "tokenizer": {
    "type": "huggingface",
    "model": "meta-llama/Llama-2-7b"
  }
}
```

### Passo 4: Usar!

```bash
python main.py --input scan.pdf --llm anthropic
```

**Auto-discovery funciona!** Não precisa modificar `llm_factory.py` se seguir a convenção:

- Provider em `src/model_management/providers/{name}_provider.py`
- Classe chamada `{Name}Provider` (PascalCase)

---

## Troubleshooting

### ❌ "LLM configuration file not found"

```
Error: LLM configuration file not found for 'ollama-local' at 'src/configs/llms/ollama-local.json'.
```

**Solução:** Verifique se o arquivo existe:

```bash
ls src/configs/llms/
# Deve incluir: gpt4.json, ollama-local.json, ollama-deepseek.json
```

### ❌ "Failed to create OllamaProvider"

```
Error: Failed to connect to Ollama at http://localhost:11434
```

**Solução:** Segure que Ollama está rodando:

```bash
ollama serve
```

### ❌ "transformers package not installed"

```
Error: transformers package not installed. Install with: pip install transformers torch
```

**Solução:** Instale dependências para HuggingFace local:

```bash
pip install transformers torch
```

### ❌ "Unknown LLM provider: 'custom'"

```
Error: Unknown LLM provider: 'custom'
To add support for 'custom':
1. Create: src/model_management/providers/custom_provider.py
...
```

**Solução:** Siga os passos em "Adicionando Novo Provider Customizado"

---

## Comparação de Performance

| Provider            | Setup    | Primeira Vez         | Por Chunk      | Custo          |
| ------------------- | -------- | -------------------- | -------------- | -------------- |
| **OpenAI**          | ✅ Fácil | Rápido               | 🟡 Lento (API) | Cobrado        |
| **Ollama Mistral**  | 🟡 Médio | Lento (baixa modelo) | ⚡ Rápido      | Grátis         |
| **Ollama DeepSeek** | 🟡 Médio | Lento (baixa modelo) | ⚡ Rápido      | Grátis         |
| **HF Remote**       | ✅ Fácil | Rápido               | 🟡 Médio (API) | Cobrado/Grátis |
| **HF Local**        | 🟡 Médio | Muito Lento          | ⚡ Rápido      | Grátis         |

---

## Arquivos Modificados (Resumo)

### 🔧 Novos Arquivos

- `src/model_management/__init__.py`
- `src/model_management/config_loader.py`
- `src/model_management/llm_factory.py`
- `src/model_management/validation.py`
- `src/model_management/providers/base_provider.py`
- `src/model_management/providers/openai_provider.py`
- `src/model_management/providers/ollama_provider.py`
- `src/model_management/providers/huggingface_provider.py`
- `src/model_management/providers/__init__.py`
- `src/configs/llms/ollama-local.json`
- `src/configs/llms/ollama-deepseek.json`
- `docs/SETUP_OLLAMA.md`
- `docs/CUSTOM_PROVIDER_TEMPLATE.md`

### ✏️ Modificados

- `src/configs/llms/gpt4.json` — Removeu `provider` redundante
- `src/utils/chunking.py` — Fixou invoke() calls, removeu emoji
- `src/utils/block_creation.py` — Limpeza de imports
- `tools/run_experiments.py` — Corrigiu argumentos metrics.py
- `tools/process_results.py` — Adicionou try/except para missing charts.py

### 🗑️ Deletados

- `src/llm_utils.py` (refactorizado para providers)
- `src/tokenizer_utils.py` (refactorizado para validation.py)

---

## Próximos Passos Opcionais

1. **Adicionar Claude (Anthropic)** — Siga template em `CUSTOM_PROVIDER_TEMPLATE.md`
2. **Adicionar Groq** — Model remoto rápido
3. **Adicionar vLLM** — Servidor OpenAI-compatible local
4. **Otimizar chunking** — Considerar streaming para evitar timeout
5. **Adicionar cache** — Reutilizar respostas para chunks iguais

---

## Documentação de Referência

- [`docs/SETUP_OLLAMA.md`](SETUP_OLLAMA.md) — Setup passo-a-passo para Ollama
- [`docs/CUSTOM_PROVIDER_TEMPLATE.md`](CUSTOM_PROVIDER_TEMPLATE.md) — Template completo para custom providers
- [`src/model_management/providers/base_provider.py`](../src/model_management/providers/base_provider.py) — Interface base

---

## Conclusão

MulitaMiner agora oferece **arquitetura LLM agnóstica** com suporte a:

- ✅ APIs comerciais (OpenAI)
- ✅ Provedores open-source (HuggingFace)
- ✅ Modelos 100% locais (Ollama)
- ✅ Custom providers via Provider Pattern

**Tudo com zero mudanças na CLI ou estrutura de outputs.** 🚀
