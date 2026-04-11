# 📋 ANÁLISE DETALHADA DO PIPELINE MULTIMINER - OPENVAS

## Pipeline Completo de Extração de Vulnerabilidades OpenVAS

```
graph TD
    A["📄 PDF OpenVAS<br/>50-500MB"] --> B["🔍 load_pdf_with_pypdf2<br/>Extrai texto bruto"]

    B --> C["📍 save_visual_layout<br/>Extrai headers com<br/>Severity/Port/Protocol"]

    C --> D["🔲 create_session_blocks_from_text<br/>OpenVASStrategy.create_blocks"]

    D --> D1["Detecta padrão:<br/>^Severity Port/Protocol<br/>Agrupa por severity"]
    D1 --> D2["Cria arquivos temporários<br/>block_High_80_tcp_1.txt<br/>block_Medium_443_https_2.txt"]

    D2 --> E["⚙️ extract_vulns_from_blocks<br/>Para cada block:"]

    E --> E1["1️⃣ split_text_to_subchunks<br/>Detecta marker: '^NVT:'<br/>Agrupa max 5 vulns<br/>Max 8000 chars"]

    E1 --> E2["2️⃣ get_token_based_chunks<br/>Para cada subchunk:<br/>Divide por tokens<br/>Max 3000 tokens"]

    E2 --> E3["🤖 retry_chunk_with_subdivision<br/>Envia para LLM<br/>Parsing JSON<br/>Retry com divisão"]

    E3 --> E4["✅ Validação LLM<br/>validate_and_normalize_vulnerability<br/>Preenche defaults<br/>Propaga port/protocol/severity"]

    E4 --> F["🔗 Consolidação<br/>central_custom_allow_duplicates<br/>Deduplica por Name<br/>Mantém mais completa"]

    F --> G["🧹 Filtragem final<br/>Remove sem description<br/>Valida campos"]

    G --> H["💾 JSON Output<br/>vulnerabilities_default_openvas.json"]

    H --> I["📊 Conversão<br/>CSV/XLSX"]

    I --> J["✨ Relatório Final"]

    style A fill:#e1f5ff
    style B fill:#fff3e0
    style C fill:#fff3e0
    style D fill:#f3e5f5
    style E1 fill:#c8e6c9
    style E2 fill:#c8e6c9
    style E3 fill:#ffccbc
    style E4 fill:#ffccbc
    style F fill:#ffe0b2
    style G fill:#ffe0b2
    style H fill:#b2dfdb
    style I fill:#f1f8e9
    style J fill:#e0f2f1
```

---

## **FASE 1: CARREGAMENTO E EXTRAÇÃO BRUTA**

### 📄 PDF → Texto Bruto

```python
# main.py - Início do processamento
doc_text = load_pdf_with_pypdf2(args.input)
visual_layout_path = save_visual_layout(doc_text, args.input, args.scanner)
```

**O que acontece:**

- PDF é lido com PyPDF2
- Texto bruto é extraído (perda de formatação visual)
- Visual layout é salvo separadamente para capturar headers (Severity/Port/Protocol)

**Código objetivo:**

```python
# src/utils/pdf_loader.py
def load_pdf_with_pypdf2(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    return text
```

✅ **Pontos Positivos:**

- Simples e rápido
- Captura todo o conteúdo

❌ **Pontos Negativos:**

- Perda de estrutura original
- Pode conter ruído/caracteres especiais

---

## **FASE 2: CRIAÇÃO DE BLOCKS (Primeira Divisão)**

### 🔲 Estratégia de Scanner - Divisão por Severity/Port/Protocol

```python
# main.py
blocks = create_session_blocks_from_text(
    doc_text,
    scanner=args.scanner
)
```

**O OpenVAS faz:**

```python
# src/scanner_strategies/openvas.py
def extract_visual_context(self, visual_layout_path: str) -> Tuple[List, None, None, None]:
    """Extrai Severity/Port/Protocol de headers do PDF"""
    for idx in range(len(layout_lines)-1, -1, -1):
        line = layout_lines[idx]
        m = self.HEADER_REGEX.match(line)  # Detecta: "Critical 80/tcp"
        if m:
            initial_severity = m.group(1)      # "Critical"
            initial_port = m.group(2)          # "80"
            initial_protocol = m.group(3)      # "tcp"
```

```python
def create_blocks(self, report_text: str, temp_dir: str, initial_context: Tuple):
    """Cria um arquivo para cada severity/port/protocol"""
    for line in lines:
        header_match = self.HEADER_REGEX.match(line.strip())
        if header_match:  # Nova seção severidade
            # Salva bloco anterior
            block_path = os.path.join(
                temp_dir,
                f"block_{bloco_severity}_{bloco_port}_{bloco_protocol}_{block_idx}.txt"
            )
            blocks.append({
                'file': block_path,
                'port': current_port,
                'protocol': current_protocol,
                'severity': current_severity
            })
```

**Estrutura de saída:**

```
temp_blocks/
├── block_Critical_443_https_1.txt   (todas vulns Critical na porta 443)
├── block_High_80_tcp_2.txt          (todas vulns High na porta 80)
├── block_Medium_8080_http_3.txt     (todas vulns Medium na porta 8080)
└── block_Low_general_tcp_4.txt      (vulns Low - porta genérica)
```

✅ **Pontos Positivos:**

- Mantém contexto de severity, port, protocol
- Agrupa vulns por contexto similar
- Facilita paralelização futura
- Propaga metadata até a validação final

❌ **Pontos Negativos:**

- Divisão fixa por headers → pode gerar muitos blocks pequenos
- Blocks muito grandes podem ficar > 100KB
- Sem balanceamento de tamanho entre blocks
- Metadados (severity/port) podem ser aplicados incorretamente se LLM extrai diferente

---

## **FASE 3: DUPLA DIVISÃO EM CHUNKS** ⚙️

### 1️⃣ **Primeira Camada: MARKER-BASED** (split_text_to_subchunks)

```python
# src/utils/block_creation.py (linha 99)
subs = split_text_to_subchunks(
    block_text,
    target_size=8000,
    profile_config=profile_config
)
```

```python
# src/utils/chunking.py
def split_text_to_subchunks(text: str, target_size: int, profile_config: dict = None):
    """
    Divide respeitando MARKERS (NVT:) e max_vulnerabilities_per_chunk
    """
    pattern_info = detect_scanner_pattern(text, profile_config)
    # pattern_info = {
    #   'scanner_type': 'openvas',
    #   'marker_pattern': '^\s*NVT:',
    #   'max_vulnerabilities_per_chunk': 5,    ← FROM CONFIG
    #   'force_break_at_markers': True,
    # }

    marker_lines = []
    for i, line in enumerate(lines):
        if re.search(pattern_info['marker_pattern'], line):
            marker_lines.append(i)  # Índices das linhas com "NVT:"

    # LÓGICA CRÍTICA: Agrupa vulns respeitando max_vulnerabilities_per_chunk
    vulns_per_chunk = pattern_info.get('max_vulnerabilities_per_chunk', 3)  # = 5 para OpenVAS

    i = 0
    while i < len(marker_lines):
        vulns_in_chunk = 0
        chunk_lines = []
        chunk_size = 0

        # Agrupa até 5 vulnerabilidades
        while i < len(marker_lines) and vulns_in_chunk < vulns_per_chunk:
            block_start = marker_lines[i]
            block_end = marker_lines[i + 1] if i + 1 < len(marker_lines) else len(lines)

            block_text = ''.join(lines[block_start:block_end])
            block_size = len(block_text)

            # Se adicionar excedera 8000 chars E já tem 1+ vuln, quebra
            if vulns_in_chunk > 0 and (chunk_size + block_size > 8000):
                break

            chunk_lines.extend(block_lines)
            chunk_size += block_size
            vulns_in_chunk += 1
            i += 1

        subchunks.append(''.join(chunk_lines))

    return subchunks
```

**Exemplo de divisão (entrada: 10 vulnerabilidades):**

```
Block Original: [Vuln1(2KB) + Vuln2(2KB) + ... + Vuln10(2KB)]

SubChunk 1: [Vuln1 + Vuln2 + Vuln3 + Vuln4 + Vuln5] = 10KB chars
SubChunk 2: [Vuln6 + Vuln7 + Vuln8 + Vuln9 + Vuln10] = 10KB chars
```

✅ **Pontos Positivos:**

- Respeita limites de vulnerabilidades inteiras
- Evita cortar vulns no meio
- Considera tamanho em caracteres
- Config customizável por scanner

❌ **Pontos Negativos:**

- **Ignore do `min_chunk_tokens`** → config lê mas nunca usa!
- Limite 8KB é fixo em código, não em config
- Pode gerar subchunks com tamanhos muito variáveis
- Não considera proporções token/caractere

---

### 2️⃣ **Segunda Camada: TOKEN-BASED** (get_token_based_chunks)

```python
# src/utils/block_creation.py (linha 103)
for s in subs:
    chunks.extend(get_token_based_chunks(
        s,
        max_tokens=max_chunk_size,        # ex: 4000
        reserve_for_response=reserve_for_response,  # ex: 1000
        tokenizer=tokenizer
    ))
```

```python
# src/utils/chunking.py
def get_token_based_chunks(text: str, max_tokens: int,
                           reserve_for_response: int = 1000,
                           tokenizer=None):
    """
    Divide por TOKENS (não por caracteres)
    """
    chunk_size = max_tokens - reserve_for_response  # 4000 - 1000 = 3000

    chunks = []
    tokens = tokenizer.encode(text)  # Tokeniza com tiktoken

    start = 0
    while start < len(tokens):
        end = min(start + chunk_size, len(tokens))
        chunk_tokens = list(tokens[start:end])
        chunk_text = tokenizer.decode(chunk_tokens)  # ⚠️ Pode cortar no meio de palavra!
        chunks.append(TokenChunk(chunk_text))
        start = end

    return chunks
```

**Visão prática (entrada: SubChunk 1 com 10KB = ~2500 tokens):**

```
SubChunk 1 (contem Vuln1-5):
    ├─ Tokeniza: [token1, token2, ..., token2500]
    ├─ chunk_size = 3000 tokens
    ├─ Resultado: 1 CHUNK  (já cabe nos 3000 tokens)
    └─ CHUNK 1: completo com [Vuln1...Vuln5]

SubChunk 2 (contem Vuln6-10):
    ├─ Tokeniza: [token1, token2, ..., token2200]
    ├─ chun_size = 3000 tokens
    ├─ Resultado: 1 CHUNK
    └─ CHUNK 2: completo com [Vuln6...Vuln10]
```

✅ **Pontos Positivos:**

- Respeita limite real de tokens (limite LLM)
- Usa tiktoken (compatível com GPT)
- Margem de segurança para resposta (`reserve_for_response`)

❌ **Pontos Negativos:**

- **Pode cortar no meio de palavras** → `tokenizer.decode()` podem gerar texto quebrado
- Nenhuma validação se corte aconteceu no meio de linha
- Se SubChunk1 = 8KB mas 4000 tokens, gera 2+ chunks → **mistura vulns entre chunks!**
- Não há sincronização com marker boundaries

---

## **FASE 4: PROCESSAMENTO NA LLM** 🤖

```python
# src/utils/block_creation.py (linha 116)
for chunk in chunks:
    prompt = build_prompt(chunk, profile_config)

    vulns = retry_chunk_with_subdivision(
        chunk, llm, profile_config, max_retries=3,
        tokenizer=tokenizer,
        max_chunk_size=max_chunk_size
    )
```

**Componentes:**

1. **Build Prompt:**

```python
# src/utils/chunking.py
def build_prompt(doc_chunk, profile_config):
    prompt_template = profile_config.get('prompt_template')
    # ex: 'src/configs/templates/openvas_prompt.txt'

    if os.path.isfile(prompt_template):
        prompt_template = load_prompt(prompt_template)

    sanitized_content = sanitize_unicode_text(doc_chunk.page_content)

    return prompt_template.replace("{context}", sanitized_content)
```

**Exemplo de prompt final:**

```
[Seu template OpenVAS aqui]

{context} substituído por:

NVT: CVE-2024-1234
Description: Cross-site Scripting...
CVSS: 9.0
...
```

2. **Invocação com Retry:**

```python
# src/model_management/llm_processing.py
def retry_chunk_with_subdivision(chunk, llm, profile_config, max_retries):
    for attempt in range(max_retries):
        try:
            response = llm.invoke(prompt)
            vulns = parse_json_response(response)
            return vulns
        except Exception as e:
            if attempt < max_retries - 1:
                # Redivide o chunk e tenta novamente
                subdivided_chunks = _subdivide_chunk(chunk)
                for sub_chunk in subdivided_chunks:
                    sub_vulns = retry_chunk_with_subdivision(...)
                    all_vulns.extend(sub_vulns)
                return all_vulns
            else:
                raise
```

✅ **Pontos Positivos:**

- Retry automático com subdivição
- Tratamento de erros de parsing JSON
- Recuperação de falhas LLM

❌ **Pontos Negativos:**

- **Sem delay entre chunks** → rate limiting não respeitado
- Retry recursivo pode gerar estruturas aninhadas complexas
- Sem logging detalhado de quando/por que foi necessário retry

---

## **FASE 5: VALIDAÇÃO E PROPAGAÇÃO DE METADATA** ✅

```python
# src/utils/block_creation.py (linha 126)
validated_vulns = []
for v in vulns_chunk:
    validated = validator(v)  # validate_and_normalize_vulnerability
    if validated:
        validated_vulns.append(validated)

# PROPAGAÇÃO DE CONTEXT
for idx, v in enumerate(vulns):
    if block.get('port') is not None:
        port_val = block['port']
        port_val_vuln = v.get('port')

        # Se é primeira vuln OR campo está vazio, propaga
        if idx == 0 or is_invalid_port(port_val_vuln):
            v['port'] = port_val

    # Mesmo para protocol e severity
    if block.get('protocol') is not None:
        v['protocol'] = block['protocol']

    if block.get('severity') is not None:
        v['severity'] = block['severity']
```

✅ **Pontos Positivos:**

- Preenche metadata faltante do contexto de block
- Validação garante estrutura esperada
- Defaults aplicados

❌ **Pontos Negativos:**

- **Sobrescreve valores LLM apenas se forem inválidos** → pode ser contraditório
- Se LLM extraiu severity diferente, a do block "vence"
- Não há log de conflitos

---

## **FASE 6: CONSOLIDAÇÃO E DEDUPLICAÇÃO** 🔗

```python
# main.py
final_vulns = central_custom_allow_duplicates(
    vulnerabilities,
    profile_config,
    allow_duplicates=False,
    output_file=output_file
)
```

```python
# src/scanner_strategies/consolidation.py
def deduplicate_by_name(vulnerabilities, field="Name"):
    """Remove duplicatas mantendo a mais completa"""
    grouped = defaultdict(list)

    for v in vulnerabilities:
        key = v.get(field)
        grouped[key].append(v)

    result = []
    for group in grouped.values():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Mantém a que tem mais campos preenchidos
            def count_filled_fields(vuln):
                return sum(1 for k, val in vuln.items()
                          if val not in [None, '', [], {}, 0])
            most_complete = max(group, key=count_filled_fields)
            result.append(most_complete)

    return result
```

✅ **Pontos Positivos:**

- Remove duplicatas mantendo versão mais completa
- Simples e determinístico
- Customizável por field

❌ **Pontos Negativos:**

- Sem merge de campos → escolhe um inteiro (perde dados se vulns tivem campos diferentes)
- "Mais completa" é por contagem simples (campo vazio vale '0')
- Sem logging de quais foram mergidas

---

## **FASE 7: FILTRAGEM FINAL** 🧹

```python
# main.py
def has_valid_description(vuln):
    desc = vuln.get("description")
    if not desc:
        return False
    if isinstance(desc, list):
        return any(str(d).strip() for d in desc)
    return bool(str(desc).strip())

removed_vulns = [v for v in final_vulns if not has_valid_description(v)]
final_vulns = [v for v in final_vulns if has_valid_description(v)]
```

✅ **Pontos Positivos:**

- Remove vulns inválidas
- Log de removidas criado

❌ **Pontos Negativos:**

- Apenas valida `description` → pode haver outras faltas
- Sem validação de campos críticos (CVSS, severity, etc)

---

## **RESUMO FINAL: IMPACTOS NO PIPELINE**

### 🎯 **Como o max_vulnerabilities_per_chunk: 5 funciona:**

| Etapa                  | Papel                              | Impacto                                   |
| ---------------------- | ---------------------------------- | ----------------------------------------- |
| **Marker (Subchunks)** | Agrupa até 5 vulns por subchunk    | Reduz para ~2 chamadas LLM vs ~5 isoladas |
| **Tokenizer**          | Subdivide cada subchunk por tokens | Varia: 1-5 chunks por subchunk            |
| **Resultado efetivo**  | Combina ambos critérios            | **2-5 vulns por chunk final**             |

### 📊 **Fluxo quantitativo (exemplo):**

```
ENTRADA: Block com 20 vulns (2KB cada = 40KB total)

FASE 1 (Marker):
  ├─ Agrupa até 5 vulns
  ├─ SubChunk 1: [V1-V5] = 10KB
  ├─ SubChunk 2: [V6-V10] = 10KB
  ├─ SubChunk 3: [V11-V15] = 10KB
  └─ SubChunk 4: [V16-V20] = 10KB

FASE 2 (Tokenizer):
  ├─ SubChunk1 (10KB=~2500 tok) → 1 CHUNK
  ├─ SubChunk2 (10KB=~2500 tok) → 1 CHUNK
  ├─ SubChunk3 (10KB=~2500 tok) → 1 CHUNK
  └─ SubChunk4 (10KB=~2500 tok) → 1 CHUNK

CHAMADAS LLM: 4 (vs 20 se isoladas!)
```

### ⚠️ **Problemas Críticos:**

1. **Falta de sincronização Marker↔Token:**
   - Marker agrupa por vulnerabilidades
   - Token divide por limite semântico
   - **Resultado pode quebrar vulns no meio**

2. **Config Ignorada:**
   - `min_chunk_tokens: 800` nunca é usado
   - `force_break_at_markers: true` é parcialmente seguido

3. **Sem margem de segurança:**
   - Se subchunk = 8001 chars mas = 4500 tokens → quebra em 2 chunks
   - Sem validação de integridade após split

---

## **RECOMENDAÇÕES DE MELHORIA:**

```python
# ❌ PROBLEMA ATUAL
subs = split_text_to_subchunks(block_text, target_size=8000)
for s in subs:
    chunks.extend(get_token_based_chunks(s, max_tokens=4000))

# ✅ POSSÍVEL MELHORIA
# 1. Passar reserve_for_response para marker-split
# 2. Validar limites token na marker-layer também
# 3. Log de reconciliações

subs = split_text_to_subchunks(
    block_text,
    target_size=7000,  # Reduzir margem
    max_tokens_estimate=max_chunk_size,
    reserve_for_response=reserve_for_response
)
for s in subs:
    chunks.extend(get_token_based_chunks(s, max_tokens=max_chunk_size))
```
