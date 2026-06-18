# 📊 Avaliação de Extração de Vulnerabilidades com LLMs

Estratégia de avaliação para o MulitaMiner: extração estruturada de vulnerabilidades a partir de relatórios de scanners (OpenVAS, Tenable WAS, PDFs) usando LLMs.

**Baseline:** anotação humana revisada por especialista. Por ser humana, requer controle de concordância inter-anotador (ver §6).

**Objetivo experimental:** comparar duas versões do pipeline de extração — **V2** (`results_runs_V2/`) vs **V3** (`results_runs/`, versão atual e canônica) — para quantificar o ganho de evolução do pipeline. V3 é tratada como referência de schema; V2 é normalizada antes de entrar nas métricas (ver §0).

---

## 🔀 0. Versionamento de Pipeline (V1 / V2 / V3)

O dataset cobre **três** pipelines do MulitaMiner com schemas distintos:

| Campo | V1 | V2 | V3 (canônico) |
| --- | --- | --- | --- |
| `cvss` | `list[7]` (`[score, null×6]`) | `list[str]` (`["10.0"]`) | `float \| None` |
| `plugin_details` | ausente | `list` | `dict` |
| `instances` | ausente | `list` | `list` |
| `plugin` | `[]` (sempre vazio) | `str \| None` | `str \| None` |
| `identification`, `http_info` | `[]` (placeholders V1) | ausentes | ausentes |
| `severity` | UPPER (`"HIGH"`) | mixed (`"HIGH"`/`"High"`) | mixed (bug do LLM) |

### Como cada versão é avaliada

**Cada versão é julgada pelo SEU PRÓPRIO schema** ("LLM compliance with own contract"), e
comparada contra o **mesmo baseline humano** em métricas baseline-anchored
(coverage, P/R/F1 por campo, BERTScore, severidade). Nada é "alinhado a V3 para
ser comparado a V3" — isso seria tautológico.

```
baseline humano (referência fixa, externa às versões)
       ↑
       │ métricas §1–§4 (baseline-anchored)
       │
       ├── V1 extrações (V1_SCHEMA)
       ├── V2 extrações (V2_SCHEMA)
       └── V3 extrações (V3_SCHEMA)
```

### Métricas tautológicas — **removidas**

A versão anterior deste documento reportava `type_coercion_rate` e "Conformance (canon → V3)"
como métricas de qualidade. **Foram retiradas** porque são auto-referentes:

| Métrica removida | Por que era tautológica |
| --- | --- |
| `type_coercion_rate` | V3 = 0 por definição (V3 já é o schema canônico — nada a coagir) |
| Schema conformance (canon → V3) | V3 ≈ 100% por definição (V3 IS V3) |
| Extra fields rate (vs V3 schema) | V3 = 0 por definição |

Reportá-las como evidência de que "V3 é melhor" é raciocínio circular. O que sobreviveu:

| Métrica mantida | Por que é evaluativa |
| --- | --- |
| `json_valid` | Mede objetivamente "o output parseia?" — não privilegia V3 |
| `schema_conformance_rate` (native) | "O LLM seguiu o prompt que recebeu?" — cada versão julgada por SEU próprio schema |
| `extra_fields_rate` (native) | "O LLM inventou campos fora do contrato?" — também native-anchored |

### Canonicalizer continua existindo

`metrics/common/schema_canonicalizer.canonicalize_to_v3()` permanece como
**preprocessador** usado por `coverage.py` antes de exact-match (V2 `cvss=["10.0"]`
precisa virar `10.0` pra bater com baseline `10.0`). Só não é mais reportado como
métrica isolada.

### Para o paper

Use métricas baseline-anchored (`ERM`, `omission_rate`, `hallucination_rate`,
`severity macro-F1`, `BERTScore`) para sustentar claims de superioridade do V3.
Não cite `type_coercion_rate` nem "canon → V3 conformance" como evidência —
revisor tier-1 vai perceber a circularidade.

---

## 🧠 Visão Geral

A avaliação ocorre em **três níveis**, nesta ordem:

1. **Schema-level** — o output é JSON válido e respeita o schema esperado?
2. **Vulnerability-level** — quais vulnerabilidades do baseline foram recuperadas pelo modelo? (alinhamento)
3. **Field-level** — para cada par alinhado, os campos batem?

> **Por que essa ordem?** Pular do nível 1 direto para o 3 enviesa toda a métrica. Se o modelo emite JSON malformado, todas as comparações de campo falham por motivo errado. Se o alinhamento é ruim, comparamos vulnerabilidade A do baseline com vulnerabilidade B do modelo — métrica fica ruído.

---

## 📐 Convenções de Agregação Multi-Run

Toda métrica neste documento segue o mesmo **pipeline de duas etapas**:

1. **Cálculo por run.** A métrica é calculada de forma independente em cada
   run de cada par (modelo, baseline). A saída é um valor por run — escalar
   ou categórico.
2. **Agregação across runs.** Os valores por run são agregados para
   visualização e relatório, com a regra dependendo do tipo da métrica.

### Regras de agregação por tipo

| Tipo de métrica | Exemplos | Regra de agregação |
| --- | --- | --- |
| Escalar | hallucination rate, omission rate, BERTScore F1, ROUGE-L, Token-F1, Field-F1, P/R/F1 por campo, ERM, Effective F1 | Média aritmética across runs (e across baselines, quando aplicável) |
| Categórica (binning por threshold) | similarity categories (Highly / Moderately / Slightly / Divergent), absent/non-existent | Contagem por categoria por run → média das contagens across runs → normaliza pelo tamanho do baseline |
| Matriz de confusão | severidade | Soma dos counts de cada célula across runs → macro-F1 calculado sobre a matriz somada |
| Booleano | JSON validity, schema conformance native | Fração de runs satisfazendo a condição |

### Por que duas etapas, e não pooling no nível de score?

LLMs são estocásticas: cada run é uma **amostra independente** do
comportamento do modelo sob aquele prompt e configuração. Agregar no nível
da métrica (e não no nível do score bruto) preserva essa variabilidade
e permite tratamento estatístico padrão (média ± desvio, Wilcoxon
pareado, etc.). Alternativas como "pooling de scores antes de
categorizar" ou "média de scores entre runs antes de calcular a métrica"
mascarariam o ruído estocástico — uma vuln classificada *Highly* em
metade dos runs e *Divergent* na outra metade vira "Moderately" no
agregado, perdendo o sinal de instabilidade.

### Escopo da agregação

- **Filtros por baseline** (ex.: gráfico de categorias por baseline)
  agregam apenas across runs daquele baseline.
- **Plots agregados** (ex.: scatter Hallucination × Omission com filtro
  "Todos") agregam across runs **e** across baselines.
- Tabelas que reportam um valor único por (modelo, versão) sempre
  agregam across runs e baselines, salvo nota em contrário.

---

## 🧱 1. Schema-Level (pré-condição)

Antes de qualquer métrica semântica, medir **fidelidade estrutural** do output.

| Métrica | O que mede | Justificativa |
| --- | --- | --- |
| **JSON validity rate** | % de runs em que o output parseia | Baseline mínima — sem JSON válido o pipeline downstream falha |
| **Schema conformance rate (native)** | % de registros conformes ao schema da PRÓPRIA versão | Mede "o LLM seguiu o prompt que recebeu?" — evaluativo cross-version |
| **Extra-fields rate (native)** | % de registros com campos fora do schema nativo | Alucinação estrutural — distinta da semântica; native-anchored é evaluativo |

> **Removidas (tautológicas):** `type_coercion_rate` e schema conformance "canon → V3"
> — ambas reduzem V3 a "vence por definição", não medem qualidade. Ver §0.

> **Por que reportar antes das demais?** LLM que falha schema com frequência distorce métricas de campo: você acaba "punindo" o modelo duas vezes (uma na coerção, outra na comparação semântica) e perde visibilidade sobre qual é a falha real.

---

## 🎯 2. Vulnerability-Level (alinhamento)

Dada a lista de N vulnerabilidades do baseline e M do modelo, casar pares antes de comparar campos.

### Procedimento

1. Construir matriz de similaridade NxM usando chave composta `(Name, port, protocol)` para OpenVAS, `(Name, severity, plugin)` para Tenable
2. Resolver matching ótimo com **Hungarian algorithm** (`scipy.optimize.linear_sum_assignment`)
3. Aceitar par apenas se similaridade ≥ limiar (sugerido: 0.85 em `Name`)

> **Por que Hungarian e não greedy?** O matching atual do MulitaMiner é greedy (composite > exact > fuzzy, com reordenação por prioridade). Funciona, mas pode tomar decisões localmente ótimas que prejudicam o matching global. Hungarian garante o ótimo global em O(N³). Para datasets pequenos (37 vulns), a diferença prática é pequena, mas blinda contra crítica metodológica em revisão.

### Métricas

| Métrica | Definição | Justificativa |
| --- | --- | --- |
| **Vuln Precision** | TP / (TP + FP) | Mede taxa de "extração correta" — quanto do que o modelo extraiu é real |
| **Vuln Recall** | TP / (TP + FN) | Mede cobertura — quanto do baseline foi recuperado |
| **Vuln F1** | média harmônica | Balanço único, comparável entre modelos |
| **Hallucination count** | FP — vulns inventadas pelo modelo | Crítico para LLM — sem isso F1 sozinho esconde alucinações |
| **Omission count** | FN — vulns perdidas | Em segurança, omissão é mais grave que invenção |

---

## 🧩 3. Field-Level (após alinhamento)

Métricas por categoria de campo, considerando o schema do MulitaMiner.

### 3.1 Campos categóricos (vocabulário fechado)

`severity` (LOG/LOW/MEDIUM/HIGH/CRITICAL), `protocol` (tcp/udp/...), `source` (OPENVAS/...).

| Campo | Métrica primária | Métricas secundárias | Justificativa |
| --- | --- | --- | --- |
| `severity` | Exact match accuracy | **Macro-F1** (classes desbalanceadas), matriz de confusão | Distribuição típica do OpenVAS é dominada por LOG; macro-F1 dá peso igual a HIGH/CRITICAL (raros e críticos). Matriz revela se erro é entre classes próximas (MEDIUM↔HIGH) ou catastrófico (LOG↔HIGH) |
| `protocol` | Exact match | — | Vocabulário pequeno e fechado; exact match basta |
| `source` | Exact match | — | Idem |

### 3.2 Campos numéricos

| Campo | Métrica primária | Justificativa |
| --- | --- | --- |
| `cvss` | Exact match | LLM **transcreve** o valor do scanner — é fidelidade de cópia, não regressão. MAE/RMSE só faria sentido se o modelo estivesse inferindo CVSS, o que não é o caso |
| `port` | Exact match | Porta é identidade, não distância: erro de 1 unidade não é "menos errado" que erro de 1000 |
| **Type-error rate** (auxiliar) | % de campos com tipo errado | Reportar separadamente porque é erro de schema, não de valor |

### 3.3 Campo de identidade

`Name` — simultaneamente texto e chave de alinhamento.

| Métrica | Quando usar | Justificativa |
| --- | --- | --- |
| **Exact match normalizado** (lowercase, strip, espaços colapsados) | Métrica primária | Name é identificador — variação em case/espaço é irrelevante para identidade |
| **Levenshtein normalizado** ou **token-set ratio** | Captura acertos com pontuação/case diferentes | Detecta casos em que o modelo acertou semanticamente mas trocou pontuação. Sem isso, "CVE-2021-1234." vs "CVE-2021-1234" conta como erro |

### 3.4 Campos de texto livre (listas de strings)

`description`, `impact`, `solution`, `insight`, `detection_result`, `detection_method`, `product_detection_result`, `log_method`.

Reportar **três níveis**:

| Nível | Métrica | Justificativa |
| --- | --- | --- |
| **Presença/ausência** | P/R/F1 binários sobre indicadora "campo preenchido" | Captura omissão e alucinação no nível do campo, separado do conteúdo. LLM que omite `solution` em metade dos casos tem problema diferente de quem preenche todos com texto ruim |
| **Lexical** | **Token-F1** (padrão SQuAD), **ROUGE-L** | Token-F1 é robusto a reordenação; ROUGE-L privilegia subsequência comum (boa para extração). BLEU é evitado: penaliza paráfrase legítima, projetado para tradução |
| **Semântico** | **BERTScore** com modelo monolíngue inglês (`roberta-large` ou `deberta-xlarge-mnli`) | LLM costuma reformular a mesma informação com palavras diferentes. Métricas lexicais penalizam isso indevidamente. BERTScore captura paráfrase semântica |

> **Por que não uma só métrica?** Cada uma captura um aspecto diferente: presença responde "o campo está lá?", lexical responde "é a mesma string?", semântico responde "é a mesma informação?". Reportar apenas semântica esconde alucinação fluente; reportar apenas lexical pune paráfrase válida.

**Estratégia para listas:** concatenado com separador para listas curtas (`solution`, `insight`); item-a-item com matching ótimo só se a lista tem itens claramente independentes (`detection_result`).

#### Categorização por threshold (gráfico de distribuição)

Para visualização agregada da similaridade textual, cada vulnerabilidade
recebe um **score consolidado por run** (média do scorer escolhido —
BERTScore F1, ROUGE-L ou Token-F1 — across campos semânticos) e é
classificada em uma categoria fixa:

| Categoria | Threshold sobre o score consolidado |
| --- | --- |
| Highly Similar | `avg > 0.70` |
| Moderately Similar | `avg > 0.60` |
| Slightly Similar | `avg > 0.40` |
| Divergent | caso contrário |
| Absent | vulnerabilidade do baseline não recuperada pelo modelo |

A categorização acontece **por run**, e a barra em cada gráfico é a média
das contagens de categoria across runs (ver §Convenções de Agregação).
Reportar "score médio across runs e depois categorizar" mascararia
instabilidade entre runs e dá uma medida diferente — ver discussão em
§4.1 sobre o porquê do binning per-run.

### 3.5 Campos de lista estruturada

| Campo | Métrica | Justificativa |
| --- | --- | --- |
| `references` | Set-based P/R/F1 após normalização. Para CVEs, extrair identificadores via regex e medir match no nível do CVE-ID | Ordem não importa; o que importa é o conjunto recuperado. Comparação string-a-string penaliza diferenças irrelevantes (URL com/sem trailing slash) |
| `instances` | Set-F1 | Idem |
| `plugin_details` | Set-F1 sobre chaves do dict; acurácia por chave | Dict precisa de duas medidas: cobertura de chaves + correção de valores |

### 3.6 Campos potencialmente sempre vazios

`plugin`, `plugin_details`, `instances` aparecem quase sempre vazios em OpenVAS. Verificar no dataset completo:
- Sempre vazios no baseline humano: presença/ausência basta. "vazio == vazio" conta como acerto.
- Ocasionalmente preenchidos: aplicar §3.5 normalmente.

---

## 📈 4. Métricas Agregadas (paper-level)

Para sustentar claims como "extração quase perfeita":

| Métrica | Definição | Justificativa |
| --- | --- | --- |
| **Effective F1** ★ | `(1 − omission_rate) × per_match_F1` | **Headline coverage-aware** — ver §4.1 abaixo |
| **Vulnerability F1 (matched)** | F1 dos pares alinhados (= `entity.F1_Score`) | Reference number; sozinho é viesado por seleção (§4.1) |
| **Exact Record Match (ERM)** | % de vulns alinhadas em que **todos** os campos batem exatamente | Métrica mais dura — sustenta a claim de "perfeita". Sem isso, médias parciais podem mascarar que nenhum registro está totalmente correto |
| **Field-level Macro Accuracy** | Média não ponderada das acurácias por campo | Campos raros (`impact`, `references`) pesam igual aos comuns — evita que campos abundantes dominem a métrica |
| **Hallucination rate** | Campos preenchidos pelo modelo onde baseline está vazio / total de campos | Normalização permite comparar entre relatórios de tamanhos diferentes |
| **Omission rate** | Campos vazios pelo modelo onde baseline tinha conteúdo / total de campos | Idem |

### 4.1 Effective F1 — por que essa métrica existe

**Problema com F1 condicionado a match (= o `entity.F1_Score` clássico)**:
ele só mede qualidade nos pares que o pipeline conseguiu alinhar. Um
pipeline conservador, que ignora vulnerabilidades difíceis, tem F1
alto **por seleção** — não porque é melhor, mas porque escolheu o que
medir. Comparar dois pipelines pelo F1 condicionado é **viesado**
quando a taxa de match difere entre eles (caso típico em comparações
cross-version: V3 alinha mais vulns difíceis que V2 ignorava → F1 médio
de V3 cai mesmo o pipeline tendo melhorado).

**Effective F1** combina cobertura com qualidade-por-match num número:

```
Effective F1 = (1 − omission_rate) × per_match_F1
             ↑ cobertura            ↑ qualidade condicional
             (penaliza skip)       (entity.F1_Score)
```

Propriedades:

- **Não-gameável por seletividade**: pipeline que skipa metade das vulns
  não consegue compensar com F1 alto nos restantes — `(1 − 0.5) × 1.0 = 0.5`.
- **Comparável cross-version**: V2 com `recall=0.73, F1=0.985` → 0.72; V3
  com `recall=0.85, F1=0.94` → 0.80 (V3 melhor — visível só com Effective F1).
- **Substitui Vulnerability F1 como headline** em todos os reports;
  Vulnerability F1 fica como métrica de referência no leaderboard.

> **Caveat de seleção** (importante pra paper §0): aumentos de cobertura
> entre versões frequentemente vêm com queda de per-match-F1 (vulns
> difíceis são, por definição, mais difíceis de extrair). Sem Effective F1
> a leitura ingênua é "V3 regrediu" — com Effective F1, fica claro que é
> trade-off favorável (geralmente +Effective F1 mesmo com -F1 condicional).

### 4.2 Triagem visual do trade-off — Recall × F1 scatter

Para cada (modelo, versão), plotar um ponto em `(recall, per-match F1)`.
**Ideal = canto superior-direito**. Iso-Effective-F1 contours (curvas
onde `recall × F1 = const`) marcam o "valor combinado" — mover-se ao
longo de um contour é redistribuição entre cobertura e qualidade
condicional sem ganho líquido. Mover-se **entre** contours pra direita-
acima é melhoria real.

Em comparações cross-version, conectar pontos do mesmo modelo entre
versões com **setas** torna o "Pareto move" óbvio visualmente — leitor
identifica em segundos se a versão nova foi pra melhor (seta cruza
contour pra cima) ou pior (seta desce contour).

---

## 🔁 5. Variabilidade entre Runs

LLMs são estocásticos mesmo com `temperature=0`. O dataset do MulitaMiner já contempla múltiplos runs (`run1..run10`).

| Prática | Justificativa |
| --- | --- |
| Reportar **média ± desvio padrão** sobre runs | Sem desvio, claim de "modelo X é melhor" pode ser ruído estocástico |
| **Coeficiente de variação (CV = σ/μ)** como métrica única de reprodutibilidade | Normaliza σ pela escala do valor — comparável entre métricas com magnitudes diferentes (F1 ∈ [0,1] vs `n_matched_pairs` ∈ [50,70]) |
| **Wilcoxon pareado** entre modelos | Não-paramétrico, pareado por relatório — adequado quando distribuições não são normais e o N é pequeno |
| **Bonferroni** se comparar mais de dois modelos | Controla taxa de falsos positivos em comparações múltiplas |

### 5.1 Bandas qualitativas de CV

Pra evitar que o leitor precise interpretar "CV = 4.7%" do zero, classificar
em 4 bandas (ajustável conforme contexto):

| Band | CV (%) | Interpretação |
| --- | --- | --- |
| **very stable** | < 2% | Run-to-run noise; ranking entre modelos confiável |
| **stable** | < 5% | Diferenças de ~5% entre modelos provavelmente reais |
| **moderate** | < 10% | Repetir N runs ou aumentar amostra antes de claims fortes |
| **unstable** | ≥ 10% | Modelo não está respondendo de forma reprodutível; investigar `temperature`, `seed`, prompt-sensitivity |

Em comparações cross-version, **Δ CV** (CV V3 − CV V2) é diagnóstico:
- Δ CV negativo significativo = "V3 ficou mais reprodutível" (prompt mais estrito, menos espaço pra LLM divergir).
- Δ CV positivo = "V3 ficou mais sensível à variação interna do LLM"; trade-off com cobertura.

---

## 👥 6. Concordância no Baseline Humano

Como o baseline é anotado por humanos, reportar concordância entre anotadores blinda contra "o ground truth é confiável?":

| Tipo de campo | Métrica | Justificativa |
| --- | --- | --- |
| Categóricos (`severity`, `protocol`) | **Cohen's κ** (dois anotadores) ou **Fleiss' κ** (três+) | κ corrige concordância pelo acaso — duas pessoas concordando em "LOG" não vale tanto se 90% das amostras são LOG |
| Numéricos (`cvss`, `port`) | % de exact agreement | Numérico não tem distribuição de probabilidade que justifique κ |
| Texto livre | Token-F1 ou BERTScore entre anotadores (concordância = ceiling) | Define o teto realista — se humanos concordam só em 92% de `severity`, exigir 99% do LLM é irreal |

---

## 📌 Resumo por Campo

| Campo | Tipo | Métrica primária | Métricas secundárias |
| --- | --- | --- | --- |
| `Name` | identidade | Exact match normalizado | Levenshtein, token-set ratio |
| `severity` | categórico | Exact match | Macro-F1, matriz de confusão |
| `cvss` | numérico | Exact match | — |
| `port` | numérico | Exact match | Type-error rate |
| `protocol` | categórico | Exact match | — |
| `source` | categórico | Exact match | — |
| `description`, `impact`, `solution`, `insight` | texto livre | Token-F1 | ROUGE-L, BERTScore, presença/ausência |
| `detection_result`, `detection_method`, `log_method`, `product_detection_result` | texto livre (lista) | Token-F1 (concatenado) | ROUGE-L, BERTScore |
| `references` | lista estruturada | Set-F1 sobre IDs normalizados | — |
| `instances` | lista estruturada | Set-F1 | — |
| `plugin_details` | dict | Set-F1 sobre chaves | Acurácia por chave |
| **Agregadas** | — | Exact Record Match, Field-level Macro Accuracy | Hallucination/Omission rate |

---

## 🗺️ Guia de visualização — qual report carrega qual métrica

Existem dois HTML reports e o set de PNGs paper-friendly. **Não duplicar
gráficos entre os reports** — cada um responde uma pergunta distinta:

| Report | Pergunta | Foco |
| --- | --- | --- |
| **Normal** (`metrics_report_*.html`) | "Como meu pipeline está performando? Onde falha?" | Análise profunda de uma versão — diagnósticos, drilldowns, per-modelo |
| **Comparação** (`metrics_comparison_*.html`) | "A versão nova melhorou? É significativo?" | Delta cross-version, trade-offs, testes pareados |
| **PNGs** (`outputs/plots/*.png`) | "Figura para o paper" | Estática, alta resolução; espelha os charts mais críticos de cada report |

### Tabela de divisão (single source of truth)

`✓` = aparece, `—` = não cabe / overlap evitado intencionalmente.
**Adicionar/mover qualquer chart deve passar por essa tabela primeiro.**

| Métrica / Chart | Normal | Comparação | PNG | Justificativa da divisão |
| --- | :---: | :---: | :---: | --- |
| **KPI hero (Effective F1, Schema validity, Severity Macro-F1, ERM)** | ✓ Best por modelo | ✓ Por versão + Δ | — | Ambos precisam de headline |
| **Leaderboard** (modelo × métrica) | ✓ Sortado por Effective F1 | ✓ Wide com Δ | — | Ambos precisam, contextos diferentes |
| **Run-to-run consistency (CV bands)** | ✓ Summary | ✓ Δ CV (Statistics) | — | Reprodutibilidade no normal; mudança entre versões no compare |
| **Precision/Recall/F1 grouped bars** | ✓ Quality | ✓ Headline (4 painéis × versão) | ✓ | Ranking inter-modelo (normal) vs cross-version (compare) |
| **Hallucination × Omission scatter** | ✓ Quality | — | ✓ | Compare tem o **Recall × F1 scatter**, mais informativo |
| **Recall × F1 scatter (com iso-Eff-F1 contours)** | ✓ Quality (sem setas) | ✓ Headline (com setas V→V) | ✓ | Trade-off — útil intra-versão e cross-version |
| **F1 boxplot across runs** | ✓ Robustness | — | ✓ | Variabilidade interna; compare não cabe |
| **Wilcoxon model × model** | ✓ Robustness | — | ✓ | "Quem é melhor" — pergunta intra-versão |
| **Wilcoxon V×V (paired)** | — | ✓ Statistics | — | Cross-version |
| **Schema conformance heatmap (model × field)** | ✓ Diagnostic | — | ✓ | Hoje 1-coluna; expande quando schema check ficar per-field |
| **Schema validity per modelo (bars)** | ✓ Diagnostic | ✓ Schema view | ✓ | Per-modelo no normal; comparison mostra V×V |
| **JSON validity rate per modelo** | ✓ Diagnostic | ✓ Schema view (V×V) | ✓ | Métrica básica em ambos |
| **Severity confusion small-multiples** | ✓ Diagnostic | — | ✓ | Per-modelo deep |
| **Per-field F1 heatmap** | ✓ Diagnostic | — | ✓ | Per-modelo deep |
| **Per-field hallucination/omission heatmap** | ✓ Diagnostic | — | ✓ | Diagnóstico per-modelo: qual campo o LLM mais alucina/omite |
| **Extra fields rate per modelo** | ✓ Diagnostic | — | — | "LLM inventou campos fora do schema?" — diagnostic intra-versão |
| **Missing fields top-N (qual campo mais omitido)** | ✓ Diagnostic | — | — | Idem |
| **Text similarity heatmaps (BERT/ROUGE/Token-F1)** | ✓ Drilldown | — | ✓ | Per-modelo, baseline-select |
| **Similarity distribution per modelo** | ✓ Drilldown | — | ✓ | Per-modelo, baseline-select |
| **Similarity distribution per versão** | — | ✓ Similarity (BERT/ROUGE toggle) | ✓ | Cross-version |
| **Most-missed vulnerabilities** (table) | ✓ Drilldown | — | — | Diagnóstico per-baseline |

### Princípios da divisão

1. **Per-modelo deep → normal**. Heatmaps grandes, drilldowns por baseline,
   confusion matrices. Comparison não consegue mostrar isso pra 2 versões
   sem ficar ilegível.
2. **Cross-version delta → comparison**. KPI cards com Δ, Wilcoxon V×V,
   leaderboard wide, similarity per versão.
3. **Reference numbers → ambos**. Effective F1 e Vulnerability F1
   aparecem nos dois — em contextos diferentes (best model vs delta).
4. **Diagnostic intra-versão → normal**. Extra fields, missing fields,
   per-field hallucination — só fazem sentido olhando o pipeline isolado.
5. **PNG = subset paper-friendly**. Inclui o que vai pra figura do paper:
   headline charts (Quality), Schema, severity confusion, similarity
   stacked. Diagnósticos puros (most-missed, extra fields tables) ficam
   só no HTML.

### Quando adicionar um chart novo

- **Pergunta diagnóstica per-modelo** → normal. Add ao Diagnostic / Drilldown.
- **Pergunta "mudou entre versões?"** → comparison. Add ao Headline / Schema / Statistics.
- **Métrica que sustenta uma claim do paper** → também PNG. Add a `png.py`.
- **Métrica derivada (combinação de outras)** → documentar fórmula em metrics.md
  ANTES de implementar.

---

## ⚠️ Considerações

- **Heterogeneidade entre fontes:** scanners codificam severidade diferente ("Severity: High" vs "Risk: 3"). Normalizar antes de comparar.
- **Determinismo de métrica:** alinhamento e métricas categóricas são reprodutíveis; BERTScore depende do modelo de embeddings — fixar versão.
- **Interpretação:** F1 baixo em texto livre não implica erro semântico — sempre cruzar com BERTScore antes de concluir.

---

# 🛠️ Status Atual vs. Proposto

Auditoria do que já está implementado em `metrics/` e o que falta.

## ✅ Já implementado

| Componente | Arquivo | Cobertura |
| --- | --- | --- |
| Matching por chave composta (`Name + port + protocol` para OpenVAS, `Name + severity + plugin` para Tenable) com wildcards | [pipelines/compare_extractions.py](metrics/pipelines/compare_extractions.py), [pipelines/compare_extractions.py](metrics/pipelines/compare_extractions.py) | §2 (parcial — greedy, não Hungarian) |
| Fallback de matching: composite → exact name → fuzzy (rapidfuzz, threshold via `FUZZY_THRESHOLD`) | mesmo | §2 |
| BERTScore F1 por campo (com modelo `distilbert-base-uncased`, fallback `roberta-large`, `bert-base-uncased`) | [pipelines/compare_extractions.py](metrics/pipelines/compare_extractions.py) | §3.4 (semântico) |
| ROUGE-L F1 por campo | [pipelines/compare_extractions.py](metrics/pipelines/compare_extractions.py) | §3.4 (lexical, parcial) |
| Entity metrics (P/R/F1 exact-match para campos determinísticos: cvss, severity, port, protocol, plugin) | [entity/compare_extractions_entity.py](metrics/entity/compare_extractions_entity.py) | §3.1, §3.2 (parcial) |
| Categorização: Highly/Moderately/Slightly Similar / Divergent / Non-existent / Absent | bert + rouge | §2 (parcial) |
| Tracking de hallucination (`UNMATCHED`, `UNMATCHED_EXCESS`) e omission (`Absent`) | bert + rouge | §2, §4 (parcial — counts, falta rate normalizado) |
| Separação de campos semânticos vs. determinísticos via `field_mapper` | [common/field_mapper.py](metrics/common/field_mapper.py) | §3 |
| Geração de plots e relatórios | [plot/](metrics/plot/) | — |

## 🔴 Faltando (gaps vs. o que o paper exige)

| Gap | Onde entra na proposta | Esforço |
| --- | --- | --- |
| **Schema-level metrics** (JSON validity + native conformance + native extra-fields) | §1 | Baixo — pode rodar antes de BERT/ROUGE |
| **Macro-F1 + matriz de confusão** para `severity` (atualmente só exact-match P/R/F1 binarizado) | §3.1 | Baixo — `sklearn.metrics.confusion_matrix` + `f1_score(average='macro')` |
| **Token-F1** (SQuAD-style) para campos de texto livre — métrica primária faltando, hoje só ROUGE-L + BERTScore | §3.4 | Baixo — implementação ~30 linhas |
| **Presença/ausência** (P/R/F1 binário sobre "campo preenchido") | §3.4 | Baixo — derivável dos dados que já temos |
| **Set-F1 com normalização de CVE-ID** para `references` | §3.5 | Baixo — regex + set ops |
| **Hungarian matching** (substituir greedy atual) | §2 | Médio — `scipy.optimize.linear_sum_assignment` é trivial, mas precisa redesenhar a função de score |
| **Aggregated metrics** (Exact Record Match, Field-level Macro Accuracy, Hallucination/Omission rate normalizados) | §4 | Médio — agregador novo lendo outputs existentes |
| **Multi-run aggregation** (média ± desvio entre run1..run10) | §5 | Médio — agregador novo |
| **Wilcoxon pareado** entre modelos (deepseek vs llama3 vs llama4 vs gpt4 vs gpt5) | §5 | Baixo — `scipy.stats.wilcoxon` |
| **Cohen's κ / Fleiss' κ** no baseline humano | §6 | Baixo se houver múltiplos anotadores; depende do design da anotação |

---

# 📋 Plano de Ação

Ordenado por **valor para o paper / custo de implementação**. Cada fase produz métricas reportáveis isoladamente.

## Fase 1 — Quick wins (1–2 dias)

Aproveita pipeline existente, adiciona métricas de baixo custo que cobrem os gaps mais críticos para revisão.

1. **Token-F1 + presença/ausência** em `compare_extractions_rouge.py` (ou novo `compare_extractions_token_f1.py`)
   - Verificação: roda em um JSON de run1 e produz coluna `*_token_f1` no `Per_Vulnerability`
2. **Macro-F1 + matriz de confusão para `severity`** em `compare_extractions_entity.py`
   - Adicionar nova aba `Confusion_Matrix` no XLSX de saída
   - Verificação: matriz exibe distribuição LOG/MEDIUM/HIGH e macro-F1 separado
3. **Schema-level metrics** — novo módulo `metrics/schema/check_schema.py`
   - Roda no JSON bruto antes da conversão para XLSX
   - Saída: `schema_report_{run}.json` com {valid_json, conformance_rate, type_errors, extra_fields}
   - Verificação: rodar nos 10 runs do deepseek e ver variabilidade

## Fase 2 — Agregação multi-run (3–5 dias)

A partir dos outputs já gerados pelos scripts atuais.

4. **Aggregator multi-run** — novo `metrics/aggregator/aggregate_runs.py`
   - Lê `bert_comparison_*.xlsx`, `rouge_comparison_*.xlsx`, `entity_metrics_*.xlsx` de `run1..runN`
   - Produz tabela: linha = (modelo, alvo, campo), colunas = média ± desvio das métricas
   - Verificação: tabela final cobre os 4 modelos × 3 alvos × 10 runs
5. **Métricas agregadas (paper-level)** — extender o aggregator
   - Exact Record Match, Field-level Macro Accuracy, Hallucination rate, Omission rate
   - Verificação: tabela final reproduz os números esperados manualmente em uma run de sanidade
6. **Wilcoxon pareado entre modelos** — `metrics/aggregator/statistical_tests.py`
   - Pareamento por (alvo, run); entrada = scores agregados por modelo
   - Saída: matriz p-valor + Bonferroni
   - Verificação: rodar em pares conhecidos (ex.: deepseek vs llama3) e checar consistência com tabelas

## Fase 3 — Refinamento metodológico (1–2 semanas)

Mudanças mais profundas que blindam contra crítica de revisor tier-1.

7. **Hungarian matching** — refatorar `process_extraction_comparison_*` para usar `linear_sum_assignment`
   - Manter a função de score atual (`key_match_score` + nome) como matriz de custo
   - Verificação: comparar resultado em um caso onde há ambiguidade clara (duplicatas de "Services") — Hungarian deve produzir matching estável
8. **Set-F1 para `references` com extração de CVE-ID** em entity ou novo módulo
   - Regex `CVE-\d{4}-\d{4,7}` + comparação set-based
   - Verificação: caso com baseline contendo lista de CVEs e modelo retornando subset
9. **Inter-rater κ no baseline** (depende de ter múltiplos anotadores)
   - Se baseline tem só um anotador: documentar como limitação
   - Se houver dois: `sklearn.metrics.cohen_kappa_score` por campo categórico
   - Verificação: reportar κ por campo no paper

## Fase 4 — Reporting (paralelo às demais)

10. **Tabelas e gráficos finais para o paper** — extender `metrics/plot/`
    - Tabela principal: campo × modelo × métrica primária (média ± desvio)
    - Heatmap de matriz de confusão para `severity`
    - Boxplot de variabilidade entre runs por modelo
    - Verificação: gráficos prontos no formato do venue alvo

---

# 🗂️ Organização Proposta (estrutura de scripts)

## Diagnóstico do estado atual

A estrutura `metrics/{common,bert,rouge,entity,plot}/` está boa como esqueleto, mas tem **dois problemas de DRY** que vão piorar conforme adicionamos métricas:

1. **Alinhamento duplicado** — `compare_extractions_bert.py` e `compare_extractions_rouge.py` repetem ~200 linhas idênticas (composite key, fuzzy matching, fallback de prioridades, tracking de `_baseline_row_id`). Adicionar token-F1 hoje significa triplicar essa lógica.
2. **Acoplamento métrica↔pipeline** — cada script é um pipeline completo (carrega XLSX, alinha, calcula, escreve XLSX). Adicionar uma métrica nova = clonar 700 linhas e trocar o `score()`.

## Princípio de organização

> **Alinhamento é executado uma vez; cada métrica é só uma função `score(pred, ref) → float`.**

Isso resolve ambos os problemas: alinhamento vira biblioteca compartilhada, métricas viram plugins.

## Estrutura proposta

```
metrics/
├── common/                    # ── já existe, só extender ──
│   ├── config.py
│   ├── normalization.py
│   ├── matching.py            # rapidfuzz helpers (já existe)
│   ├── field_mapper.py
│   ├── sheet_resolver.py
│   ├── cli.py
│   ├── aligner.py             # ★ NOVO — extrai composite_key + Hungarian
│   └── io.py                  # ★ NOVO — load/save XLSX padronizado
│
├── scorers/                   # ★ NOVO — cada métrica = 1 função pura
│   ├── __init__.py            # registry: {"bertscore": fn, "rouge_l": fn, ...}
│   ├── bertscore.py           # score(pred, ref) -> float (cache do modelo aqui)
│   ├── rouge_l.py
│   ├── token_f1.py            # ★ NOVO
│   ├── exact_match.py         # ★ NOVO — categóricos/numéricos/Name
│   ├── set_f1.py              # ★ NOVO — references, instances
│   └── presence.py            # ★ NOVO — binário "campo preenchido"
│
├── pipelines/                 # ★ NOVO — orquestradores finos
│   ├── compare_extractions.py # substitui bert+rouge — chama aligner + scorers
│   ├── schema_check.py        # ★ NOVO — roda no JSON cru, antes do XLSX
│   ├── entity_metrics.py      # mantém o entity atual (já é thin)
│   └── confusion_severity.py  # ★ NOVO — macro-F1 + matriz para severity
│
├── aggregators/               # ★ NOVO — pós-processamento multi-run
│   ├── multi_run.py           # média ± desvio sobre run1..runN
│   ├── coverage.py            # Exact Record Match, Hallucination/Omission rate
│   └── statistical_tests.py   # Wilcoxon pareado + Bonferroni
│
├── interrater/                # ★ NOVO — concordância no baseline humano
│   └── kappa.py               # Cohen's / Fleiss' κ
│
└── plot/                      # ── já existe ──
    └── ...
```

## Como cada gap do plano de ação cai na estrutura

| Gap | Onde implementar |
| --- | --- |
| Schema-level metrics | `pipelines/schema_check.py` (roda no JSON cru) |
| Token-F1, presença/ausência | `scorers/token_f1.py`, `scorers/presence.py` + registrar no scorer registry |
| Macro-F1 + matriz `severity` | `pipelines/confusion_severity.py` |
| Set-F1 com CVE-ID | `scorers/set_f1.py` (com normalizador via regex em `common/normalization.py`) |
| Hungarian matching | `common/aligner.py` (única implementação consumida por todos os pipelines) |
| Multi-run aggregation | `aggregators/multi_run.py` |
| Métricas agregadas (ERM + halluc/omission) | `pipelines/coverage.py` |
| Wilcoxon | `aggregators/statistical_tests.py` |
| Cohen's κ | `interrater/kappa.py` |

## Boas práticas que isso aplica

- **DRY** — alinhamento mora em um lugar só (`common/aligner.py`), não copiado entre `bert/` e `rouge/`
- **KISS** — `scorers/*.py` são funções puras de 5–30 linhas; sem estado, sem I/O
- **Open/Closed** — adicionar uma métrica nova = criar arquivo em `scorers/` e registrar; nenhum código existente muda
- **Single Responsibility** — pipelines orquestram I/O e ordem; scorers calculam; aggregators agregam; cada um tem uma razão para mudar
- **Testabilidade** — scorers puros são triviais de testar com `assert score("foo", "foo") == 1.0`; antes era impossível sem montar XLSX inteiro

## Estratégia de migração (não-destrutiva)

Para evitar quebrar o pipeline atual durante a refatoração:

1. **Fase A** — criar `common/aligner.py` extraindo a lógica duplicada; `bert/` e `rouge/` passam a importar dela. Comportamento idêntico, código menor.
2. **Fase B** — criar `scorers/` e mover `bertscore_score()` / `rouge_l_score()` para lá. Pipelines antigos importam dos scorers.
3. **Fase C** — criar `pipelines/compare_extractions.py` unificado que recebe lista de scorers via CLI (`--scorers bertscore,rouge_l,token_f1`). Os scripts antigos `bert/` e `rouge/` viram aliases finos para o novo pipeline.
4. **Fase D** — adicionar scorers e pipelines novos do plano de ação **sem tocar** no que já roda.

> **Vantagem prática:** os outputs de `runX/` já gerados continuam compatíveis. Nada precisa ser regerado para a refatoração entrar.

---

# 📊 Visualizações (PNG + HTML)

## Princípio

| Formato | Uso | Características |
| --- | --- | --- |
| **PNG** ([png_generator.py](metrics/plot/png_generator.py)) | Paper / submissão | Estático, alta resolução, paleta amigável a impressão, eixos completos com legenda |
| **HTML** ([report_generator.py](metrics/plot/report_generator.py) + Plotly) | Análise interna / exploração | Interativo, hover, zoom, drill-down por modelo/run/campo |

> **Regra:** todo gráfico do paper deve existir em PNG; o HTML é superset (mesmos gráficos + extras exploratórios). Evitar gráficos que só existam em HTML — viram dívida de comunicação.

## Já implementado

- Similarity distribution stacked (por modelo) — PNG
- Matched rate + recall — PNG
- Below-HS pies (composição do que não é "Highly Similar") — PNG
- Absent / Non-existent — PNG
- Report HTML com Plotly dark theme

## ⚠️ Adaptação dos gráficos existentes

Os PNGs atuais foram desenhados quando só existiam BERTScore + ROUGE-L como métricas semânticas. **Não migram diretamente** para o novo conjunto:

| Gráfico atual | O que muda | Ação |
| --- | --- | --- |
| **Similarity stacked** (Highly/Moderately/Slightly/Divergent) | Hoje usa média de BERTScore (ou ROUGE-L) por vulnerabilidade. Com token-F1 + presence + BERTScore como métricas distintas, "similaridade" deixa de ser unidimensional. Escolher uma só métrica para categorizar é reducionista. | (a) Manter como variante "BERTScore-only" (consistência histórica) **e** (b) criar versão multi-métrica: bars empilhadas com 3 sub-bars (presence / token-F1 / BERTScore) por modelo. Decidir qual vai no paper. |
| **Thresholds de categoria** (>0.7 highly, 0.6–0.7 moderately, 0.4–0.6 slightly) | Calibrados para BERTScore com `rescale_with_baseline=True`. Token-F1 e presence têm distribuições muito diferentes — o mesmo corte 0.7 não significa "altamente similar" em token-F1. | Recalibrar thresholds **por métrica**, ou adotar percentis (p25/p50/p75) em vez de cortes absolutos. Documentar a escolha. |
| **Below-HS pies** | Depende da categorização acima — herda o mesmo problema. | Reaproveita a calibração nova; código do pie em si não muda. |
| **Matched rate / Recall** | Mede vulnerabilidades alinhadas com sucesso. Quando Hungarian substituir o greedy atual (Fase 3 do plano), a contagem muda — pares que o greedy prendia no fuzzy podem mover para composite, e vice-versa. | Re-rodar sobre os mesmos runs depois da Fase 3 e comparar. Se a diferença for grande, reportar ambas as versões na tabela do paper com nota metodológica. |
| **Absent / Non-existent** | Mesmo motivo: contagem deriva do alinhamento. | Idem — re-rodar pós-Hungarian. |

> **Regra prática:** todo gráfico atual continua válido como **diagnóstico interno** e na trilha do HTML. Para o **paper**, re-gerar depois da Fase 3 (Hungarian + thresholds calibrados) e usar a versão final.

### Refatoração mínima necessária

Antes de adicionar gráficos novos, três mudanças nos existentes:

1. **Parametrizar a métrica de categorização** — `generate_similarity_pngs()` hoje assume `Avg_BERTScore_F1`. Trocar para `score_column` parâmetro, com default mantido para retrocompatibilidade.
2. **Externalizar thresholds** — mover `0.7 / 0.6 / 0.4` para `metrics/plot/themes.py` (ou `common/config.py`) como dict por métrica: `{"bertscore": (0.7, 0.6, 0.4), "token_f1": (...), "rouge_l": (...)}`.
3. **Rerun script idempotente** — garantir que regenerar PNGs de uma run não dependa de estado antigo. Hoje há overwrite implícito; OK, mas confirmar antes da Fase 4.

## Gráficos propostos (mapeados às novas métricas)

### Schema-level (§1)

| Gráfico | Tipo | PNG | HTML | Justificativa |
| --- | --- | --- | --- | --- |
| **JSON validity rate por modelo** | Bar chart horizontal | ✓ | ✓ | Métrica binária simples; comparação direta entre modelos |
| **Schema conformance heatmap (native)** (modelo × campo, % de conformidade vs schema nativo) | Heatmap | ✓ | ✓ | Identifica visualmente em qual campo cada modelo falha mais (LLM compliance) |

### Vulnerability-level (§2)

| Gráfico | Tipo | PNG | HTML | Justificativa |
| --- | --- | --- | --- | --- |
| **Precision/Recall/F1 por modelo** (clustered bars) | Bar chart agrupado | ✓ | ✓ | Trio canônico — sustenta a claim principal |
| **Hallucination vs Omission** (scatter, eixo X = halluc rate, Y = omission rate, ponto = modelo) | Scatter | ✓ | ✓ | Trade-off visual entre os dois erros; modelo ideal é canto inferior-esquerdo |
| **Sankey baseline → modelo** (TP/FP/FN como fluxos) | Sankey | — | ✓ | Bonito mas pesado; só HTML |

### Field-level (§3)

| Gráfico | Tipo | PNG | HTML | Justificativa |
| --- | --- | --- | --- | --- |
| **Matriz de confusão `severity`** (LOG/LOW/MEDIUM/HIGH/CRITICAL) por modelo | Heatmap (5×5) | ✓ | ✓ | Critical para revisão — mostra se erro é entre classes próximas ou catastrófico |
| **Comparação tripla por campo textual** (presence / token-F1 / BERTScore lado a lado) | Grouped bars (3 séries por campo) | ✓ | ✓ | Justifica a escolha das três métricas em §3.4: cada uma conta uma história diferente |
| **Boxplot de score por campo** (distribuição de BERTScore por modelo) | Boxplot | ✓ | ✓ | Mostra dispersão, não só média — outliers são informativos |
| **Field-level macro accuracy heatmap** (modelo × campo) | Heatmap | ✓ | ✓ | Visão geral em um único gráfico |
| **Radar plot por modelo** (eixos = campos, área = qualidade) | Radar | — | ✓ | Bonito para exploração, mas radar é controverso em paper |

### Multi-run (§5)

| Gráfico | Tipo | PNG | HTML | Justificativa |
| --- | --- | --- | --- | --- |
| **Variabilidade entre runs** (boxplot de F1 por modelo, N pontos = runs) | Boxplot | ✓ | ✓ | Mostra estocasticidade — fundamenta a média ± desvio reportada |
| **Curva de convergência** (média móvel do F1 sobre runs) | Line chart | — | ✓ | Diagnóstico: se F1 não estabiliza, N de runs é insuficiente |
| **p-valor heatmap Wilcoxon** (modelo × modelo, com Bonferroni) | Heatmap | ✓ | ✓ | Mostra quais comparações são significativas; essencial em revisão estatística |

### Inter-rater (§6)

| Gráfico | Tipo | PNG | HTML | Justificativa |
| --- | --- | --- | --- | --- |
| **κ por campo** (bar chart com linha de κ=0.6 / κ=0.8 como referências) | Bar chart | ✓ | ✓ | Define o ceiling humano por campo — referência crítica para interpretar resultados do LLM |
| **Modelo vs ceiling humano** (mesmo eixo: F1 do modelo + κ humano) | Bar chart sobreposto | ✓ | ✓ | Visualmente honesto: mostra se o LLM está "no nível humano" ou abaixo |

### Agregadas (§4)

| Gráfico | Tipo | PNG | HTML | Justificativa |
| --- | --- | --- | --- | --- |
| **Exact Record Match por modelo** | Bar chart | ✓ | ✓ | Métrica única e dura — boa para abrir a seção de resultados |
| **Quadrante hallucination × omission rate** com modelos plotados | Scatter | ✓ | ✓ | Equivalente normalizado da §2; usar quando comparando entre datasets de tamanhos diferentes |
| **Dashboard summary** (4 cards: Vuln-F1, Severity Macro-F1, Text BERTScore, Exact Record Match) | Grid de KPIs | — | ✓ | Visão executiva no topo do relatório HTML |

## Convenções visuais (manter consistência com o que existe)

- **Paleta de modelos** — manter o `MODEL_COLORS` já definido em [plot_generator.py:33](metrics/plot/plot_generator.py#L33). Cada modelo tem cor fixa em todos os gráficos.
- **Paleta de similaridade** — `SIMILARITY_COLORS` já definido (verde→cyan→amber→rose→muted). Usar a mesma escala em qualquer gráfico que reporte categorias de qualidade.
- **Tema** — dark para HTML (já implementado), light minimalista para PNG (paper). Função utilitária em `plot_generator.py` deve receber `theme="paper"|"dark"`.
- **Tamanho** — PNG em 300 DPI mínimo, proporção 16:9 para gráficos largos, 1:1 para heatmaps/matrizes de confusão.
- **Anotações** — todo PNG do paper deve ter título, legenda, eixos rotulados e fonte (footnote com modelo de embeddings, N de runs).

## Como organizar no código

Seguindo a estrutura proposta em §"Organização Proposta":

```
metrics/plot/
├── plot_generator.py          # já existe — PlotlyTheme + MetricsPlotter
├── png_generator.py           # já existe — funções por gráfico
├── report_generator.py        # já existe — orquestra HTML
├── data_collector.py          # já existe
│
├── charts/                    # ★ NOVO — uma função por tipo de gráfico
│   ├── schema.py              # validity, conformance heatmap
│   ├── vulnerability.py       # P/R/F1, halluc-vs-omission scatter
│   ├── field.py               # confusion matrix, triple-metric bars, boxplots
│   ├── multirun.py            # boxplot runs, wilcoxon heatmap
│   └── interrater.py          # kappa bars, model-vs-ceiling
│
└── themes.py                  # ★ NOVO — extrair THEME_COLORS, MODEL_COLORS, SIMILARITY_COLORS
```

> **Por que separar `charts/`?** Hoje `png_generator.py` mistura coleta de dados, layout e renderização. Conforme adicionamos 15+ gráficos novos, esse arquivo vira monólito. Dividir por *categoria de métrica* (não por tipo de chart) preserva localidade — quem mexe em §3 mexe em `charts/field.py`.

---

# 🔌 Integração CLI (main.py / run_experiments)

## Princípio

**Toda nova métrica deve ser invocável pela mesma CLI que `bert`/`rouge`/`entity`** —
caso contrário, vira ilha e ninguém roda em produção.

Convenção:

- Cada pipeline aceita `parse_arguments_common` (de [metrics/common/cli.py](metrics/common/cli.py)):
  `--baseline-file`, `--extraction-file`, `--output-dir`, `--llm`, `--allow-duplicates`.
- O nome do método (passado via `--metrics`) é a chave em
  [`METRIC_SCRIPTS`](main.py) — dispatch table em `main.py`.
- Pipeline novo = uma entrada em `METRIC_SCRIPTS` + (opcionalmente) inclusão em `ALL_METHODS_ORDER`.

## Métodos disponíveis

| Método | Script | Depende de | Saída |
| --- | --- | --- | --- |
| `bert` | `metrics/pipelines/compare_extractions.py` `--scorer bertscore` | — | `bert_comparison_*.xlsx` |
| `rouge` | `metrics/pipelines/compare_extractions.py` `--scorer rouge_l` | — | `rouge_comparison_*.xlsx` |
| `entity` | `metrics/entity/compare_extractions_entity.py` | bert ou rouge | `entity_metrics_*.xlsx` |
| `schema` | `metrics/pipelines/schema_check.py` | JSON cru (deriva do `--extraction-file`) | `schema_report_*.json` |
| `severity` | `metrics/pipelines/confusion_severity.py` | bert ou rouge | `severity_confusion_*.xlsx` |
| `coverage` | `metrics/pipelines/coverage.py` | bert ou rouge | `coverage_*.xlsx` (ERM + halluc/omission) |
| **`all`** | meta-método | — | tudo acima, na ordem de `ALL_METHODS_ORDER` |

> Para scorers novos (token_f1, presence, set_f1, etc.) use o pipeline unificado [`metrics/pipelines/compare_extractions.py`](metrics/pipelines/compare_extractions.py) com `--scorer NAME --method greedy|hungarian`. Ele produz o mesmo formato de XLSX (Per_Vulnerability + Summary + Categorization + Mapping_Debug) compatível com aggregator/entity/severity/paper downstream.

`ALL_METHODS_ORDER` = `[schema, bert, rouge, entity, severity]` — schema primeiro (sem dependências, opera no JSON cru), bert/rouge produzem os pares casados que entity e severity consomem.

## Uso

```bash
# Métrica única
python main.py --input report.pdf --baseline-path baseline.xlsx \
    --metrics bert

# Várias métricas
python main.py --input report.pdf --baseline-path baseline.xlsx \
    --metrics bert rouge schema severity

# Tudo de uma vez
python main.py --input report.pdf --baseline-path baseline.xlsx \
    --metrics all

# Em batch via run_experiments
python tools/run_experiments.py --metrics all ...
```

`expand_evaluation_methods()` em `main.py` deduplica e respeita ordem; métodos desconhecidos viram warning, não erro.

## Como adicionar uma métrica nova (checklist)

1. Implementar pipeline em `metrics/pipelines/<nome>.py` consumindo `parse_arguments_common`.
2. Adicionar em `METRIC_SCRIPTS` (e em `ALL_METHODS_ORDER` se deve rodar no `all`).
3. Atualizar tabela "Métodos disponíveis" acima.
4. Atualizar `--metrics` help em [tools/run_experiments.py](tools/run_experiments.py).

---

# ✅ TODO

A lista consolidada de tarefas (fases, status, prioridades, pós-paper) está
em [TODO.md](TODO.md) na raiz do projeto. Este arquivo (`metrics.md`) é o
documento de **metodologia/teoria** — para acompanhar progresso e checklists,
use o `TODO.md`.

