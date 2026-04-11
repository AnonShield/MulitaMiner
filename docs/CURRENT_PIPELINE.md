# MulitaMiner - Pipeline Atual (v2.0)

**Última atualização:** 11 de abril de 2026  
**Status:** Ativo com Smart Chunking, Token Tracking, e Tenable Pair Handling removido

---

## 📊 Visão Geral do Pipeline

```
PDF Input
    ↓
[1] Load & Extract Text
    ↓
[2] Detect Scanner Type
    ↓
[3] Create Session Blocks (Scanner-Specific)
    ↓
[4] Smart Chunk Processing
    ├─ Apply Marker-Based Segmentation
    ├─ Respect Token Limits
    ├─ Respect Vulnerability Count Limits
    └─ Respect 8KB Character Limits
    ↓
[5] Process Each Chunk via LLM
    ├─ Build Prompt from Template
    ├─ Invoke LLM
    ├─ Parse JSON Response
    ├─ Validate JSON & Token Count
    └─ Retry on Error (with Subdivision)
    ↓
[6] Extract Vulnerabilities with Metadata
    ├─ Propagate Port/Protocol from Block Context
    └─ Propagate Severity
    ↓
[7] Consolidation (Scanner-Specific)
    ├─ Merge Duplicates by Key
    ├─ Keep Most Complete Versions
    └─ Custom Logic per Scanner
    ↓
[8] Validation & Normalization
    ├─ Field Mapping
    ├─ Type Validation
    └─ CAIS-Specific Rules (if applicable)
    ↓
[9] Format Conversion
    ├─ JSON → CSV
    ├─ JSON → XLSX
    └─ Optional Metrics & Reports
    ↓
Output Files
```

---

## 🔄 Fluxo Detalhado por Fase

### Fase 1: Load & Extract Text

**Arquivo:** `main.py` → `pdf_loader.py`

```python
# Entrada: arquivo PDF
pdf_path = "report.pdf"

# Processamento
text, page_images = load_pdf_with_pypdf2(pdf_path)
visual_layout_path = save_visual_layout(page_images)

# Saída: texto extraído + layout visual (opcional)
```

**O que acontece:**

- Lê todas as páginas do PDF
- Extrai texto e imagens
- Salva layout visual temporário (usado por OpenVAS para contexto)

---

### Fase 2: Detect Scanner Type

**Arquivo:** `main.py` + `utils/chunking.py`

```python
# Auto-detecta scanner ou usa argumento --scanner

scanner_type = detect_scanner_type(text) or args.scanner
profile_config = load_profile(scanner_type)
llm_config = load_llm(args.llm)
```

**Scanners suportados:**

- `openvas` - NVT-based reports
- `tenable_was` - Tenable Web Application Scanner
- `nessus` - Tenable Nessus
- `qualys`, `rapid7`, `default` - Genérico

**Configurações carregadas:**

```json
{
  "scanner_name": "tenable_was",
  "reader": "tenable",
  "chunking": {
    "scanner_type": "tenable_was",
    "marker_pattern": "^\\s*VULNERABILITY\\s+(CRITICAL|HIGH|MEDIUM|LOW)\\s+PLUGIN\\s+ID\\s+\\d+",
    "force_break_at_markers": true,
    "preserve_vulnerability_blocks": true,
    "max_vulnerabilities_per_chunk": 3
  },
  "prompt_template": "path/to/template.txt",
  "llm_config": "reference_to_llm.json"
}
```

---

### Fase 3: Create Session Blocks (Scanner-Specific)

**Arquivo:** `block_creation.py` + `scanner_strategies/`

```python
blocks = create_session_blocks_from_text(
    report_text=text,
    temp_dir='temp_blocks',
    visual_layout_path=visual_layout_path,
    scanner=scanner_type
)
```

**Estratégia OpenVAS:**

- Parse linhas de header: `Critical 443/tcp`
- Agrupa vulnerabilidades por severidade + porta + protocolo
- Extrai contexto visual (primeiras e últimas linhas)
- Cria arquivo separado por grupo para processamento paralelo

**Estratégia Tenable:**

- Parse padrão: `VULNERABILITY CRITICAL PLUGIN ID 12345`
- Cria blocos únicos (uma grande vulnerabilidade por bloco)
- Extrai metadados do header

**Estratégia Nessus/Qualys/Genérica:**

- Fallback: cria único arquivo com todo o texto

**Saída por bloco:**

```json
{
  "file": "temp_blocks/block_critical_443_tcp_1.txt",
  "port": "443",
  "protocol": "tcp",
  "severity": "critical"
}
```

---

### Fase 4: Smart Chunk Processing

**Arquivo:** `utils/chunking.py` → `smart_chunk_vulnerabilities()`

**Restrições Simultâneas:**

1. **Marker-based**: Quebra exatamente nos marcadores `^NVT:` ou `^VULNERABILITY`
2. **Token Limit**: Respeita `max_tokens - reserve_for_response`
3. **Vuln Count**: Agrupa no máximo N vulnerabilidades por chunk
4. **Character Size**: Máximo 8KB por chunk

```python
chunks = smart_chunk_vulnerabilities(
    text=block_content,
    marker_pattern=r'^\s*NVT:\s',          # Scanner-specific
    max_tokens=4000,                        # De llm_config.max_chunk_size
    reserve_for_response=1000,              # De llm_config.reserve_for_response
    max_vulnerabilities_per_chunk=5,        # De profile_config.chunking
    tokenizer=tiktoken.encoding_for_model("gpt-3.5-turbo"),
    scanner_type=scanner_type               # Para ajustes Tenable
)
```

**Algoritmo Smart Chunk:**

```
Para cada chunk:
  vuln_count = 0
  token_count = 0
  char_count = 0

  Enquanto houver vulnerabilidades:
    Se adicionar próxima vuln vai ultrapassar QUALQUER limite:
      Se já tem ≥1 vuln: SALVA chunk e começa novo
      Se é primeira: FORÇA incluir mesmo que grande
    Senão: adiciona vuln ao chunk
```

**Especial Tenable:**

- Reduz `max_vulnerabilities_per_chunk` pela metade (ex: 3 → 1 ou 2)
- Motivo: cada vulnerability pode ter array `instances` que expande tamanho
- NOTA: Tenable pair handling foi removido em Apr/2026 (LLM já garante instances sempre presente)

**Saída:**

```python
[
  TokenChunk(page_content="NVT: vuln1 text..."),
  TokenChunk(page_content="NVT: vuln2 text...")
]
```

---

### Fase 5: Process Each Chunk via LLM

**Arquivo:** `utils/block_creation.py` → `extract_vulns_from_blocks()`  
**Dependência:** `chunking.py` → `retry_chunk_with_subdivision()`

**Fluxo para cada chunk:**

```python
for chunk in chunks:
    # 5A: Build Prompt
    prompt = build_prompt(chunk, profile_config)
    # Substitui {context} com sanitized chunk content

    # 5B: Invoke LLM
    response = llm.invoke(prompt)

    # 5C: Parse JSON
    json_data = parse_json_response(response.content)
    tokens_output = count_tokens(response.content)

    # 5D: Validate
    validation = validate_json_and_tokens(response, chunk.page_content, max_tokens, prompt)

    if validation['json_valid'] and validation['token_valid']:
        # ✅ Sucesso
        vulnerabilities.extend(json_data)
    else:
        # ❌ Erro: Retry com Subdivision
        result = retry_chunk_with_subdivision(
            doc_chunk=chunk,
            llm=llm,
            profile_config=profile_config,
            scanner_type=scanner_type
        )
        vulnerabilities.extend(result['vulnerabilities'])
        tokens_output += result['tokens_output']
```

**Retry com Subdivision (se falha na primeira tentativa):**

```python
def retry_chunk_with_subdivision():
    # 1. Tenta LLM direto 2x mais
    # 2. Se falhar: subdivide chunk em SUBCHUNKS menores
    #    └─ Usa split_text_to_subchunks() com marker-aware
    # 3. Processa cada subchunk individualmente
    # 4. Agrupa vulnerabilidades extraídas
    # Retorna: {'vulnerabilities': [...], 'tokens_output': N}
```

**Prompts (Template Sistema):**

Cada scanner tem template específico em `src/configs/templates/`:

- **OpenVAS prompt**: Instrui LLM a extrair NVT fields, CVSS, QoD
- **Tenable prompt**: Instrui LLM que TODAS vulns têm `instances[]`
- **Default prompt**: Schema genérico JSON

Exemplo Tenable (trecho):

```
Extraction Instructions:
- Each vulnerability MUST have an "instances" array (empty list if no instances found)
- Merge Base information + Instances into ONE JSON object
- Even if vulnerability appears alone, include "instances": []
- Structure:
  {
    "Name": "...",
    "Description": "...",
    "instances": [
      {"ip": "...", "port": "..."},
      ...
    ]
  }
```

---

### Fase 6: Extract Vulnerabilities with Metadata

**Arquivo:** `block_creation.py` → `extract_vulns_from_blocks()`

**O que acontece após LLM retornar JSON:**

```python
# Para cada vulnerability extraída do LLM:
for vuln in json_data:
    # 1. Propaga metadados do BLOCO para cada vuln
    vuln['port'] = block['port']              # De block metadata
    vuln['protocol'] = block['protocol']      # De block metadata
    vuln['severity'] = block['severity']      # De block metadata (se não tiver)

    # 2. Preserva tokens processados
    vuln['_tokens_used'] = tokens_output

    # Debug: imprime extração
    print(f"✅ Extracted: {vuln['Name']} from {block['port']}/{block['protocol']}")
```

**Rastreamento de Tokens:**

- `tokens_initial`: tokens do chunk original
- `tokens_output`: tokens da resposta LLM
- `tokens_retry`: tokens usados em retries/subchunks
- **Total = tokens_initial + tokens_output + tokens_retry**

---

### Fase 7: Consolidation (Scanner-Specific, Modular)

**Arquivo:** `scanner_strategies/consolidation.py`

**Objetivo:** Consolidar/mesclar duplicatas baseado em regras do scanner e flag `--allow-duplicates`

**Lógica Modular:**

Cada scanner define **QUANDO** seu custom deve ativar via `get_custom_activation_value()`:

```python
consolidated = central_custom_allow_duplicates(
    vulnerabilities=all_vulns,
    profile_config=profile_config,
    allow_duplicates=args.allow_duplicates  # CLI flag
)
```

**Sistema de Ativação:**

1. **Cada scanner define** quando seu custom ativa:
   ```python
   def get_custom_activation_value(self):
       return True         # Custom ativa quando allow_duplicates=True
       # ou
       return False        # Custom ativa quando allow_duplicates=False
       # ou
       return {True, False}  # Custom ativa em AMBOS os casos
       # ou
       return None         # Sem custom (sempre usa default)
   ```

2. **Sistema verifica**:
   - Se `allow_duplicates` bate com `get_custom_activation_value()` → **executa custom**
   - Caso contrário → **executa default behavior**

**Comportamento DEFAULT:**
```python
# Quando custom NÃO ativa:
if allow_duplicates is True:
    return vulnerabilities  # Sem modificação
else:
    return deduplicate_by_name(vulns)  # Remove duplicatas por Name
```

**Comportamento CUSTOM por Scanner:**

| Scanner | Custom Ativa Em | Lógica |
|---------|-----------------|--------|
| **OpenVAS** | `allow_duplicates=True` | Agrupa por (Name, port, protocol) - consolida |
| **Tenable** | `allow_duplicates=False` | Agrupa por (Name, plugin) e merge instances |
| **Genérico** | Nunca (sem custom) | Usa default sempre |

**Exemplos:**

```bash
# OpenVAS - quer consolidação custom (port/protocol)?
python main.py --input report.pdf --scanner openvas --allow-duplicates
# → Roda CUSTOM (consolida por port/protocol)

# OpenVAS - quer apenas dedup simples?
python main.py --input report.pdf --scanner openvas
# → Roda DEFAULT (dedup por Name)

# Tenable - quer manter separado?
python main.py --input report.pdf --scanner tenable --allow-duplicates
# → Roda DEFAULT (sem modificação)

# Tenable - quer consolida + merge instances?
python main.py --input report.pdf --scanner tenable
# → Roda CUSTOM (consolida + merge instances)
```

---

### Fase 8: Validation & Normalization

**Arquivo:** `model_management/__init__.py`

```python
validator = get_validator(profile_config)  # Escolhe CAIS ou padrão

validated_vulns = []
for vuln in consolidated_vulns:
    # Normaliza tipos, mapeia campos, valida regras
    normalized = validator(vuln)

    if normalized:
        validated_vulns.append(normalized)
    else:
        # Log de erro se falhar validação
        print(f"❌ Validation failed: {vuln['Name']}")
```

**Validators:**

- **Standard:** `validate_and_normalize_vulnerability()`
  - Valida tipos de dados
  - Mapeia campos conhecidos
  - Remove campos vazios

- **CAIS:** `validate_cais_vulnerability()` (se profile tem `"is_cais": true`)
  - Aplica schema CAIS rigoroso
  - Valida enums (Severity, Status, etc)
  - Valida relacionamentos

---

### Fase 9: Format Conversion

**Arquivo:** `converters/`

```python
execute_conversions(
    data=validated_vulnerabilities,
    output_format=args.convert,           # 'json', 'csv', 'xlsx' ou lista
    output_dir=args.output_dir,
    scanner_type=scanner_type,
    profile_config=profile_config
)
```

**Conversores:**

| Formato        | Arquivo             | Lógica                            |
| -------------- | ------------------- | --------------------------------- |
| JSON (default) | `base_converter.py` | Salva direto + metadata           |
| CSV            | `csv_converter.py`  | Flatten JSON, escapa strings      |
| XLSX           | `xlsx_converter.py` | Múltiplas abas (vulns + metadata) |

**Saída JSON:**

```json
{
  "vulnerabilities": [
    {
      "Name": "CVE-2021-1234",
      "Description": "...",
      "Severity": "High",
      "port": "443",
      "protocol": "tcp",
      "instances": [{ "ip": "1.2.3.4" }]
    }
  ],
  "metadata": {
    "extraction_date": "2026-04-11T10:30:00",
    "scanner": "tenable_was",
    "total_processed": 150,
    "total_extracted": 142,
    "errors": 8,
    "tokens_used": 45000
  }
}
```

---

## 📝 Configurações Críticas

### LLM Config Example: `gpt4.json`

```json
{
  "model_name": "gpt-4",
  "api_key": "${OPENAI_API_KEY}",
  "max_chunk_size": 4000,
  "reserve_for_response": 1000,
  "temperature": 0.0,
  "max_retries": 3
}
```

### Scanner Config Example: `tenable.json`

```json
{
  "scanner_name": "tenable_was",
  "reader": "tenable",
  "requires_visual_layout": false,
  "chunking": {
    "scanner_type": "tenable_was",
    "marker_pattern": "^\\s*VULNERABILITY\\s+(CRITICAL|HIGH|MEDIUM|LOW)\\s+PLUGIN\\s+ID\\s+\\d+",
    "force_break_at_markers": true,
    "preserve_vulnerability_blocks": true,
    "max_vulnerabilities_per_chunk": 3
  }
}
```

---

## 🛠️ Token Tracking System

**Implementado em:** `chunking.py` + `block_creation.py`

```
Total Tokens = tokens_initial + tokens_output + tokens_retry

Fase de Tracking:
1. smart_chunk_vulnerabilities()
   └─ Calcula tokens de CADA vuln via count_tokens()
   └─ Respeita: vuln_tokens < chunk_size_tokens

2. LLM Processing (primeira tentativa)
   └─ tokens_output = encode(response.content)

3. Retry com Subdivision
   └─ tokens_retry += todos tokens de subchunks
   └─ tokens_retry += tokens de reruns LLM

4. Reporte Final
   └─ metadata.tokens_used = total
   └─ metadata.tokens_cost = total * (price_per_token)
```

**Ver:** `utils/tokens_cost.py` para cálculo de custo

---

## 🔍 Debug & Monitoring

**Pontos de Log (tqdm output):**

```
✅ [CHUNK] Attempt 1: JSON is valid!              # Sucesso primeira tentativa
⚠️  [CHUNK] Performing intelligent redivision...  # Começando retry
[CHUNK] Subchunk 1/5 processed                   # Iterando subchunks
❌ [CHUNK] Subchunk 3 did not return valid JSON  # Falha subchunk
🔄 [CONSOLIDATION] Merged 150 → 142 vulns       # Após consolidação
✅ [CONVERSION] Saved to output.json              # Conversão completa
```

---

## 📊 Métricas & Reports

**Opcional:** `metrics/` e `tools/metrics_report.py`

```python
# Compara extração vs baseline (se fornecido)
# Gera relatórios ROUGE, BERT similarity, etc
```

---

## 🚨 Error Handling Strategy

```
Falha JSON no Chunk
  ├─ Retry 1: LLM novamente (same prompt)
  ├─ Retry 2: LLM novamente (with error context)
  ├─ Fallback: intelligent_chunk_redivision()
  │   ├─ Particiona chunk em subchunks
  │   ├─ Processa cada subchunk
  │   └─ Agrupa resultados
  └─ Final: Log erro se todas falhas

Falha Validação JSON
  ├─ Check: JSON bem-formado?
  ├─ Check: Campos obrigatórios presentes?
  ├─ Check: Tipos corretos?
  └─ Descarta se falhar todos checks
```

---

## 🔄 Recent Changes (Apr 2026)

✅ **Removido:**

- ❌ `validate_base_instances_pairs()` - Tenable sempre retorna `instances[]`
- ❌ `has_pairs` field em configs - Não necessário
- ❌ `min_chunk_tokens` field - Nunca usado

✅ **Refatorado:**

- 🔄 `retry_chunk_with_subdivision()` - Agora recebe `scanner_type` diretamente (sem re-detectar)
- 🔄 `split_text_to_subchunks()` - Limpo, sem lógica de pair-handling
- 🔄 Configs de scanner - Menor, mais focado

✅ **Implementado:**

- ➕ `smart_chunk_vulnerabilities()` - Respeita 4 constraints simultaneamente
- ➕ Token tracking end-to-end
- ➕ CAIS validation profile

---

## 🎯 Usage Example

```bash
# Básico
python main.py --input report.pdf --scanner tenable_was --llm gpt4

# Com conversão
python main.py --input report.pdf --llm gpt4 --convert json csv xlsx

# Com validação e comparação
python main.py --input report.pdf \
  --scanner openvas \
  --llm gpt4 \
  --baseline baseline.json \
  --evaluation-methods rouge bert entity

# Com duplicatas permitidas
python main.py --input report.pdf --allow-duplicates
```

---

**Documento Criado:** 11/04/2026  
**Responsável:** MulitaMiner Pipeline Team  
**Status:** ✅ Estável
