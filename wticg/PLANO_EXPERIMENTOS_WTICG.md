# Plano de Experimentos — Paper WTICG

**Título de trabalho (EN):** Evaluating Local LLMs for Privacy-Preserving Vulnerability Extraction from Security Reports
**(PT):** Avaliação de LLMs locais para extração de vulnerabilidades com preservação de privacidade a partir de relatórios de segurança

**Janela:** 3 dias de experimento · 2 máquinas com GPU
**Status:** plano fechado, pronto para execução

---

## 1. Motivação e gancho

Relatórios de scanners de segurança (OpenVAS, Tenable) descrevem, em detalhe, a superfície de ataque de uma organização. O MulitaMiner, hoje, envia *chunks* desses relatórios para APIs de LLM externas (OpenAI/Groq/DeepSeek) — fato registrado no próprio README. Isso implica **vazamento de informação sensível para terceiros**, com risco de conformidade (LGPD, cláusulas contratuais) e de exposição da própria postura de segurança.

A pergunta central é prática e ainda pouco explorada na literatura de IC/graduação:

> **É possível executar a extração inteiramente local (on-premise), em hardware acessível, sem perder qualidade a ponto de inviabilizar o uso?**

Esta é uma contribuição **distinta** do paper principal (dataset de 6.700 vulnerabilidades + comparação multi-LLM em cloud): aqui o objeto de estudo é o trade-off **privacidade × qualidade × custo operacional** de modelos locais.

---

## 2. Perguntas de pesquisa

- **RQ1 — Qualidade:** quão perto da referência cloud (DeepSeek) chegam modelos locais de 4–9B em BERTScore, ROUGE-L e F1 (recall/precision por nome+host)?
- **RQ2 — Custo operacional:** qual o custo de manter a extração local em latência por relatório, throughput (tokens/s), pico de VRAM e **taxa de falha de schema** (modelo que não produz o JSON estruturado válido)?
- **RQ3 — Especialização de domínio:** um modelo local **especializado em segurança** (Foundation-Sec-8B) extrai melhor que generalistas do mesmo porte?
- **RQ4 — "Bom o suficiente":** existe configuração local que feche o trade-off qualidade × privacidade × hardware para um time de SecOps real?

---

## 3. Decisões técnicas e justificativas

### 3.1 Por que local vs. cloud (e não outra coisa)

O gargalo do MulitaMiner em cloud é **rede + custo monetário**, não computação local. Trazer a inferência para máquinas próprias muda a natureza do problema: elimina o vazamento (privacidade), troca custo por OPEX/CAPEX de hardware, e torna as **2 máquinas o objeto do experimento**, não apenas um meio de paralelizar. Por isso o eixo local×cloud é o que melhor aproveita os recursos disponíveis e gera contribuição original.

### 3.2 Seleção de modelos

Critério: **maximizar parâmetros úteis e aderência a saída estruturada (JSON) dentro do limite de 12 GB de VRAM**, cobrindo **diversidade de família** e usando **a versão mais recente de cada uma**. Recência só desempata — o que importa para a tarefa (prompt → JSON longo) é seguir instrução e respeitar schema, não a data de lançamento.

| Modelo | Backend | Porte | Justificativa técnica |
|---|---|---|---|
| **gemma4:e4b** | Ollama | 4B efet. / 8B total | Família Gemma; ancora o extremo inferior pelo eixo de **parâmetros efetivos** (~4B ativos/token). Transparência: 8B totais na memória (~10 GB) — reportar como "4B efetivos / 8B totais" (§3.6). |
| **Qwen3 8B** | Ollama | ~8B | Melhor da faixa em aderência a JSON/instrução; forte multilíngue. |
| **Llama 3.1 8B** | Ollama | ~8B | Generalista onipresente; **base de controle** das duas especializações de segurança (Foundation-Sec e Primus). |
| **Ministral 3 8B** | Ollama | ~9B | *Function calling*/JSON nativos; contexto 256k. *(candidato a corte por orçamento — ver §3.5).* |
| **Phi-4 14B** | Ollama | ~14B | Ponto alto generalista; roda na 5080 (16 GB). |
| **Foundation-Sec-1.1-8B-Instruct** | HF (4-bit) | ~8B | Especialista cibersegurança #1 (Cisco), contexto 64k; ver §3.3. |
| **Llama-Primus-Merged** | HF (4-bit) | ~8B | Especialista cibersegurança #2 (Trend Micro); ver §3.3. |
| **gpt-oss-20b** | Ollama | ~21B (MoE, ~3.6B ativos) | Modelo aberto da OpenAI (*reasoning model*); roda com **`think:"low"`** (`think:false` gera `content` vazio/instável) + `max_tokens 6000`. Validado na 5080 (~114 vulns/Artifactory). |
| **DeepSeek** | Cloud (máquina de dev) | — | **Referência** cloud; rodado *fresh* (ver §3.4). |

**Espectro de tamanho:** por **parâmetros efetivos/ativos**, vai de **~4B (gemma4:e4b)** → 8B (cluster generalista + especialistas) → 14B (Phi-4) → 21B totais / ~3,6B ativos (gpt-oss, MoE). Transparência: gemma4:e4b (MatFormer) e gpt-oss (MoE) têm **total ≠ ativos** — reportar os dois números. Os mais pesados (Phi-4 14B, gpt-oss) ficam na **5080**; o **gpt-oss-20b** (~16 GB) é validado **por último**, por não caber folgado nos 16 GB, e o **Ministral 3 8B** é o candidato natural a corte se o tempo apertar.

### 3.3 Os dois especialistas de segurança via HF (RQ3 controlada)

A RQ3 ganha força com **dois** modelos especializados em cibersegurança, ambos derivados do **mesmo base Llama-3.1-8B** do generalista de controle:

- **Foundation-Sec-1.1-8B-Instruct** (Foundation AI / Cisco, nov/2025): Llama-3.1-8B com pré-treino contínuo em cibersegurança, *instruction-tuned* + RLHF. A v1.1 **estende o contexto de 4k → 64k** — resolve o gargalo da versão anterior.
- **Llama-Primus-Merged** (`trendmicro-ailab`, Trend Micro AI Lab): Llama-3.1-8B-Instruct com pré-treino em ~2,77 bi de tokens de cyber + *fine-tuning* de instrução, *merged* preservando a capacidade de seguir instrução (+14,84% em benchmarks de cyber vs. o base).

Ambos só existem (em versão instruct utilizável) no **HuggingFace** — não no Ollama. O port do Ollama (`FenkoHQ/Foundation-Sec-8B`) **não serve**: é o **base** (não instruct) e um tag **fp16 de 16 GB** (não cabe na 12 GB). É a justificativa correta para usar o HF: **disponibilidade de modelo**. O provider reescrito carrega ambos em **4-bit nf4** (~5–6 GB), cabendo na 3060.

**Comparação-estrela (RQ3, controlada):**

> **Llama 3.1 8B (generalista)** vs. **Foundation-Sec-8B** vs. **Llama-Primus-Merged** — mesmo base, mesmo tamanho; a única variável é o *fine-tuning* de domínio. Com **duas** especializações independentes (Cisco e Trend Micro), a pergunta deixa de ser anedótica e vira um **mini-estudo controlado**: a especialização de domínio ajuda a extração de vulnerabilidade de forma *consistente*?

**Caveats registrados:**
- **Foundation-Sec 1.1:** contexto **64k** (a v1.1 corrigiu o limite de 4k da versão anterior) → *chunk* normal, mesmo prompt dos demais, **sem confound**. Licença: **Llama 3.1 Community License** (base Meta) + **Apache 2.0** (mudanças Cisco) — ok para pesquisa/publicação.
- **Primus:** herda o contexto do Llama 3.1 → também *chunk* normal. Licença **MIT** (+ Llama 3.1 Community).
- Ambos rodam em **CUDA** (na **5080**, junto com o Llama de controle — ver §4), não na máquina Windows/AMD.

### 3.4 Por que DeepSeek como referência cloud, rodado *fresh*

DeepSeek foi o melhor custo-benefício no paper principal. Aqui ele é a **linha de base de qualidade** que os locais tentam alcançar. Os números **não** são reaproveitados do paper anterior: DeepSeek é re-executado nos **mesmos baselines, mesma estratégia de dedup, mesmas 5 runs**, garantindo comparação *apples-to-apples*. O custo de API é baixo.

**Execução:** o DeepSeek roda na **máquina de dev** (chamada de API, sem GPU), em paralelo — liberando as 2 GPUs inteiramente para os modelos locais. Termina em horas.

### 3.5 Dados e protocolo de avaliação

- **Baselines com ground truth** construídos por especialistas: Juice Shop (34 vulns, ~24 pág.), bBWA (58), Artifactory 5.11.0 (116, ~175 pág.). *Em avaliação:* dropar a **Artifactory** (maior e mais lenta) e rodar só as 2 menores — ganha tempo, mas **perde toda a severidade Critical** (só a Artifactory tem) e reduz o GT de 208 → 92 vulns. Decisão pendente conforme o custo medido no D1 (meio-termo possível: Artifactory só a 2–3 runs ou só no DeepSeek + 1–2 locais-chave).
- **5 runs por (modelo × baseline)** → permite reportar **média ± desvio** e capturar variância de geração. **Plano B:** cair para 3 runs se o D2 atrasar (~40% menos compute).
- **Métricas de qualidade** (pipeline já existente): `bert`, `rouge`, `entity`, `severity`, `coverage`, `schema_check`.
- **Métricas de sistema:**
  - *Já capturadas:* latência por run (checkpoint `elapsed_time`), tokens in/out + custo (`results_tokens/` + final report), validação de schema.
  - *Deriváveis (sem código novo):* tokens/s (tokens ÷ tempo), nº de *chunks*/chamadas por relatório (log da run), retries / `json_repair` (log) como sinal de fragilidade de schema.
  - *Implementado* (`src/utils/gpu_sampler.py` + integrado no `run_experiments`): um **sampler `nvidia-smi`** em background por run que, no mesmo loop, coleta **VRAM pico** (`memory.used`), **energia GPU em Wh** (integral de `power.draw`) e **utilização** (`utilization.gpu`), gravados no checkpoint ao lado do `elapsed_time`. Só em runs locais (`get_provider_key=="local"`); no-op gracioso onde não há `nvidia-smi`. A energia é da **placa GPU** (não inclui CPU/sistema).
  - ⚠️ **Cross-GPU:** latência/tokens-s/energia **não** são comparáveis entre a 5080 e a 3060 — ver §4 (agrupar o que for comparado na mesma GPU + passe de calibração). VRAM pico e falha de schema continuam comparáveis.
  - ⚠️ **PC compartilhado:** o sampler mede a **GPU inteira**; numa máquina compartilhada (ex.: a da facu), latência/VRAM/energia ficam **contaminadas** se houver outro uso concorrente. As métricas de custo só valem em **janela exclusiva** da GPU.
- Dedup: `--allow-duplicates` (recomendado para OpenVAS).

### 3.6 Janela de contexto e *chunking* por modelo

⚠️ **Custo do prompt:** o template OpenVAS tem **~2.813 tokens** (instruções + schema + 2 exemplos), medido com tiktoken. Isso consome a janela **antes** de qualquer conteúdo. Regra de orçamento:

```
prompt(2813) + max_chunk_size + reserve_for_response ≤ num_ctx
```

**num_ctx via API (resolvido):** o `ChatOllama` do langchain **não propagava** o `num_ctx`, deixando os modelos no contexto default. O `OllamaProvider` foi **reescrito** para chamar `/api/chat` direto (via `requests`) enviando `options.num_ctx` em toda requisição → agora o `num_ctx` do JSON **aplica de verdade**, por modelo, sem Modelfile. **Verificado:** `ollama ps` mostrou `CONTEXT 16000` no gemma4 (= valor do config, e cabe nos 12 GB da 3060 a 100% GPU). Idem nos demais Ollama.

| Modelo (`--llm`) | Backend | Máquina | num_ctx | max_chunk_size | reserve_resp | max_tokens | Nota |
|---|---|---|---|---|---|---|---|
| Qwen3 8B (`qwen3_local`) | Ollama | 3060 | 16000 | 10000 | 3000 | 2500 | folgado |
| Ministral 3 8B (`ministral3`) | Ollama | 3060 | 16000 | 10000 | 3000 | 2500 | 256k nativo; 16k basta |
| gemma4:e4b (`gemma4`) | Ollama | 3060 | 16000 | 10000 | 3000 | 2500 | **8B total** (4B efetivos) → ~10 GB; cabe a 16k na 3060 (validado: 100% GPU no `ollama ps`) → padronizado com os demais |
| Llama 3.1 8B (`llama31_local`) | Ollama | 5080 | 16000 | 10000 | 3000 | 2500 | folgado |
| Phi-4 14B (`phi4`) | Ollama | 5080 | 16000 | 10000 | 3000 | 2500 | ~9 GB em Q4 → cabe nos 16 GB da 5080; 16k é o teto nativo do Phi-4 |
| Foundation-Sec 1.1 (`foundation_sec`) | HF 4bit | 5080 | — (64k, uso ~16k) | 10000 | 3000 | 2500 | sem num_ctx (limite = arquitetura) |
| Primus (`primus`) | HF 4bit | 5080 | — (Llama) | 10000 | 3000 | 2500 | sem num_ctx |
| gpt-oss-20b (`gpt_oss`) | Ollama | 5080 | 16000 | 10000 | 3000 | **6000** | **`think:"low"`** (reasoning model: `think:false` dá `content` vazio/instável); `max_tokens` maior p/ caber raciocínio + JSON no mesmo orçamento. Validado (~114 vulns no Artifactory) |

**Contexto uniforme (16000/10000):** todos os Ollama locais usam **16000/10000** — inclusive o **gemma4:e4b**, que apesar do nome é **8B total** (~10 GB) mas **cabe a 16k na 3060** (validado no `ollama ps`: 100% GPU), então foi padronizado com os demais (a versão antiga 12000/6000 foi descartada e o modelo re-rodado). Os HF (Foundation-Sec/Primus) não têm `num_ctx` — o limite é a arquitetura; o controle é só o `max_chunk_size`. Constantes: `reserve_for_response 3000`, `temperature 0.0`, e `max_tokens 2500` — **exceto o gpt-oss-20b**, que usa **`max_tokens 6000` + `think:"low"`** por ser *reasoning model*: o raciocínio compartilha o orçamento de saída (`num_predict`), e com `think:false` o raciocínio estoura o teto e o `content` sai **vazio** (achado registrado em §3.2/§7).

---

## 4. Hardware e divisão das máquinas

| Recurso | VRAM | Papel |
|---|---|---|
| **RTX 5080** | 16 GB | nó local rápido (Blackwell, sm_120); cabe até Phi-4 14B (~9 GB Q4). gpt-oss-20b (~16 GB) fica apertado — §3.2/§7 |
| **RTX 3060** | 12 GB | nó local; **referência de "hardware acessível"** para o custo |
| Windows + RX 6600 | — | dev/orquestração + DeepSeek (API cloud) + métricas em CPU |

**Estratégia: dividir os modelos entre as máquinas** (cada modelo roda em UMA máquina), não rodar todos em ambas — é o mais rápido. É seguro porque **qualidade (BERT/ROUGE/F1) independe de hardware** (greedy/`temperature=0` → mesmo output em qualquer GPU).

**Mas as métricas de custo não são todas comparáveis entre GPUs diferentes:**

| Métrica | Comparável cross-GPU? |
|---|---|
| Qualidade (BERT/ROUGE/F1) | ✅ independe de HW |
| VRAM pico | ✅ depende do modelo, não da placa |
| Falha de schema, retries | ✅ depende do modelo |
| **Latência / tokens-s / energia** | ❌ **depende da GPU** |

Dois cuidados para salvar a comparação de custo:
1. **Agrupar na mesma GPU o que for comparado em custo** → o **trio da RQ3 (Llama + Foundation-Sec + Primus) fica todo na 5080**, então "generalista vs especialista" em latência/energia é justo.
2. **Passe de calibração:** rodar **1–2 modelos nas DUAS GPUs** (1 baseline, 1 run) para medir a razão **5080↔3060** e normalizar as latências cross-GPU ("equivalente-3060"). Custo ~20–30 min.

### Divisão dos modelos
| 5080 (16 GB, rápida) | 3060 (12 GB) |
|---|---|
| Phi-4 14B + **Foundation-Sec 1.1** + **Primus** + **Llama 3.1 8B** + **gpt-oss-20b** | Qwen3 8B + Ministral 3 8B\* + gemma4:e4b (+ o futuro <8B) |
| os pesados (Phi-4, 2 HF, gpt-oss\*\*) **+ o trio RQ3 junto** | os leves |

- **DeepSeek** na máquina Windows (API, não toca GPU), em paralelo.
- Dentro de cada máquina os modelos rodam **em sequência** (1 GPU não comporta 2 sem OOM) — serialização via `get_provider_key="local"`.
- **Config por modelo:** todos os Ollama locais usam **16000/10000** (inclusive o **gemma4:e4b**, que cabe a 16k na 3060). Como cada modelo roda numa única GPU, não há divergência de config para o mesmo modelo entre máquinas.

**Tempo estimado:** ~11 h (5080) / ~12 h (3060) → **wall ~12 h**. Folgado em 3 dias mesmo só com essas 2 máquinas.

\* Ministral 3 8B é candidato a corte (§3.2).

\*\* gpt-oss-20b (~16 GB) é validado **por último**: não cabe folgado nos 16 GB da 5080 — pode exigir num_ctx menor ou ser cortado (§3.2, §7).

- **DeepSeek (cloud)** roda em paralelo na máquina Windows (API, não toca GPU).
- Dentro de cada máquina os modelos rodam **em sequência** — uma 3060 não comporta dois modelos simultâneos sem OOM. A serialização é garantida pelo agrupamento `get_provider_key="local"` (que passou a incluir `huggingface`). Entre as máquinas, paralelismo total.

---

## 5. Cronograma

### Dia 1 — Setup e *smoke test* → **saída: lineup e configs validados**

1. Instalar Ollama nas 2 máquinas. **Atenção:** Ministral 3 exige Ollama **0.13.1 (pre-release)**; se houver atrito, *fallback* para `mistral` (7B v0.3, estável).
2. `ollama pull` dos modelos Ollama: gemma4:e4b, Qwen3 8B, Llama 3.1 8B, Ministral 3 8B, Phi-4 14B (e **gpt-oss:20b** na 5080 — **validar se cabe nos 16 GB**; se estourar, reduzir num_ctx ou cortar, §3.2). **Verificar** o `num_ctx` aplicado com `ollama ps` (já validado: gemma4 = 12000).
3. Na **5080**, preparar o ambiente HF: `uv sync --extra hf-local`; baixar **Foundation-Sec-1.1-8B-Instruct e Llama-Primus-Merged**; validar carga em 4-bit e VRAM. **Atenção Blackwell:** a 5080 é **sm_120** com driver 595.80 / **CUDA 13.2** — confirmar que o build de **PyTorch + bitsandbytes** suporta sm_120 (senão o 4-bit não carrega); usar wheels recentes / *nightly* se preciso (§7).
4. **Validar** o sampler de VRAM/energia (já implementado) gravando no checkpoint; testar o `think:false` do gpt-oss (A/B no `thinking` da resposta).
5. *Smoke test*: 1 baseline (Juice Shop) **e** 1 da Artifactory × cada modelo. Verificar parse/JSON e medir o tempo — **calibra a estimativa de D2** e decide runs do Phi-4/gpt-oss (5 vs 3) e o destino da Artifactory.
6. Travar configs definitivas.

### Dia 2 — Batch → **saída: extrações + métricas brutas**

- Disparar `tools/run_experiments.py` em cada máquina com seu subconjunto (§4), `--metrics all --runs-per-model 5 --allow-duplicates`, com **checkpoint** ligado.
- DeepSeek (cloud) em paralelo na máquina Windows.
- VRAM/energia/latência são capturadas **automaticamente no checkpoint** (sampler de GPU); nada manual.
- Pode rodar *overnight* (checkpoint resume execuções interrompidas).

### Dia 3 — Análise e escrita → **saída: tabelas, figuras e texto**

- `tools/process_results.py` para gráficos; consolidar `aggregated_metrics.xlsx`.
- Montar tabelas/figuras (§6) e redigir (~8 páginas, formato WTICG).
- *Se sobrar tempo:* 1 modelo local sobre subset de ~10 relatórios → parágrafo de escalabilidade; ou BERTScore com backbone **SecureBERT** (semântica *domain-aware*) como métrica alternativa.

---

## 6. Entregáveis (tabelas e figuras)

- **T1 — Qualidade local vs. cloud** (BERT/ROUGE/F1, média ± desvio) por baseline.
- **T2 — Custo operacional** (latência/relatório, tokens/s, pico de VRAM, **energia GPU em Wh**, util %, % falha de schema).
- **F1 — Fronteira de Pareto** qualidade × latência (e variante qualidade × energia), com privacidade como dimensão categórica (local = privado / cloud = exposto).
- **T3 — Confusão de severidade + coverage** (erra mais na priorização Critical/High?).
- **T4 — Especialização de domínio** (RQ3): Llama 3.1 8B vs. **Foundation-Sec-8B** vs. **Llama-Primus-Merged** nas mesmas métricas (a especialização ajuda de forma consistente?).

### T5 — Custo monetário real do cloud (DeepSeek-v4-flash)

Custo **real** (não estimativa) da referência cloud, do `usage` retornado pela API (`results_tokens/usage_real_*.jsonl`), preços v4-flash (USD/1M: cache-hit 0,0028 · cache-miss 0,14 · output 0,28).

**Por componente** — o output domina (96%); o cache cobriu 92% do input:

| Componente | Tokens | Preço (USD/1M) | Custo |
|---|---:|---:|---:|
| cache *hit* (input) | 5.574.912 | 0,0028 | $0,0156 |
| cache *miss* (input) | 498.103 | 0,14 | $0,0697 |
| **output** | 7.120.910 | 0,28 | $1,9939 |
| **TOTAL** | 13.193.925 | | **$2,0792** |

**Por baseline** — Artifactory = 73% do custo (relatório maior + mais *retries* do cloud):

| Baseline | runs | custo total | custo/run |
|---|---:|---:|---:|
| Juice Shop | 5\* | $0,1400 | $0,0280 |
| bBWA | 5 | $0,4177 | $0,0835 |
| Artifactory | 5 | $1,5215 | **$0,3043** |
| **TOTAL** | 15 | **$2,0792** | |

\* O `usage_real` é nomeado por PID e não grava baseline/run; o split foi reconstruído pelo volume de input e pela **sequência de `input_tokens` por chunk** (quase determinística por relatório). **Todos os 15 runs estão presentes**: o 5º run do JuiceShop não se perdeu — o SO **reusou o PID 28112**, anexando dois runs no mesmo arquivo (a 2ª metade da sequência é idêntica ao run limpo de 16 chunks). Logo o JuiceShop são **5 runs em 4 arquivos**; o total e os componentes já o incluem (re-rodar geraria um 16º, superestimando). Corrigido daqui pra frente gravando `target`/`run` no registro (§usage_log).

---

## 7. Riscos e mitigações

| Risco | Mitigação |
|---|---|
| VRAM apertada na 3060 (gemma4:e4b ~10 GB) | **Validado:** cabe a num_ctx 12000 (100% GPU no `ollama ps`). |
| HF em bitsandbytes mais lento que GGUF (Foundation-Sec, Primus) | Isolados na **5080** (rápida) junto com o Phi-4; balanceia o tempo de parede. |
| Phi-4 14B lento no relatório grande (Artifactory) | Na 5080; calibrar no D1; reduzir runs ou dropar a Artifactory (§3.5). |
| Ollama pre-release (Ministral 3) instável | *Fallback* para `mistral` 7B v0.3 estável. |
| D2 atrasa | Cair de 5 → 3 runs; cortar o Ministral; dropar a Artifactory. |
| Modelo local quebra o JSON | É **resultado** (RQ2 — taxa de falha de schema), não falha do experimento. |
| 129 relatórios inviável local em 3 dias | Escopo restrito aos baselines com ground truth; escalabilidade vira nota de D3. |
| GPU compartilhada (PC da facu) contamina latência/energia | Rodar as métricas de custo em **janela exclusiva** da GPU (§3.5). |

---

## 8. Configs (criados em `src/configs/llms/`)

**Todos os configs do lineup já foram criados.** Ollama (`temperature: 0.0`, `max_chunk_size`, `reserve_for_response`, `options.num_ctx`, `tokenizer`):

- `qwen3_local.json`, `llama31_local.json`, `ministral3.json`, `phi4.json`, `gemma4.json` (todos **16000/10000**), `gpt_oss.json` (**`"think": "low"`**, `max_tokens 6000`).

Especialista #1 (HF, **contexto 64k** na v1.1 → chunk normal, mesmo prompt dos demais):

```json
{
  "provider": "huggingface",
  "model": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct",
  "temperature": 0.0,
  "quantization": "4bit",
  "max_tokens": 2500,
  "max_chunk_size": 10000,
  "reserve_for_response": 3000,
  "tokenizer": { "type": "huggingface", "model": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct" }
}
```

Especialista #2 (HF, contexto do Llama 3.1 → chunk normal):

```json
{
  "provider": "huggingface",
  "model": "trendmicro-ailab/Llama-Primus-Merged",
  "temperature": 0.0,
  "quantization": "4bit",
  "max_tokens": 2500,
  "max_chunk_size": 10000,
  "reserve_for_response": 3000,
  "tokenizer": { "type": "huggingface", "model": "trendmicro-ailab/Llama-Primus-Merged" }
}
```

Referência cloud: `deepseek.json` (já existe).

---

## 9. Links relevantes

**Especialistas em segurança (HF — via provider HF/bitsandbytes):**
- Foundation-Sec-1.1-8B-Instruct (Cisco, contexto 64k, Llama 3.1 Community + Apache 2.0) — https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct
- Llama-Primus-Merged (Trend Micro, MIT + Llama 3.1 Community) — https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged

**Modelos locais (Ollama — confirmar tags no D1):**
- Qwen3 8B — https://ollama.com/library/qwen3
- Llama 3.1 8B — https://ollama.com/library/llama3.1
- Ministral 3 8B (exige Ollama 0.13.1 pre-release) — https://ollama.com/library/ministral-3
- Gemma 4 (e4b) — https://ollama.com/library/gemma4
- Phi-4 14B — https://ollama.com/library/phi4
- gpt-oss-20b (só na 5080, `think:false`) — https://ollama.com/library/gpt-oss

**Referência cloud:**
- DeepSeek (API) — https://platform.deepseek.com

> Nota: o port `FenkoHQ/Foundation-Sec-8B` do Ollama **não** é usado (é o *base*, não instruct, e fp16 de 16 GB) — por isso o Foundation-Sec vai via HF na versão instruct 1.1.

**Ideia de métrica (D3, se sobrar tempo):**
- SecureBERT (backbone *domain-aware* para BERTScore) — https://huggingface.co/ehsanaghaei/SecureBERT

**A confirmar no D1:**
- `num_ctx` aplicado em todos via `ollama ps` (já validado: gemma4 = 12000).
- VRAM do Phi-4 14B e do gpt-oss-20b na 5080; gemma4:e4b na 3060 (já validado ~10 GB).
- NOTICE.md do Foundation-Sec 1.1 (uso de pesquisa/publicação).
