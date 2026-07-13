# Schema — fonte única de verdade

Registro do que foi feito e, principalmente, **por que** — pra ninguém refazer os
experimentos que já rodamos (e pagamos).

Complementa o [`SCHEMA_PROPOSAL.md`](SCHEMA_PROPOSAL.md) (schema híbrido futuro) e a
[`docs/EXTENSIBILITY.md`](../../docs/EXTENSIBILITY.md) (como adicionar scanner).

---

## 1. O problema

O "schema V3" (a lista de campos que a ferramenta extrai) vivia copiado à mão em
**vários lugares que divergiam em silêncio**:

- os prompts (`configs/prompts/openvas_prompt.txt`, `tenable_prompt.txt`);
- o validador de métrica (`metrics/pipelines/schema_check.py`, um dict `V3_SCHEMA`);
- as categorias de métrica (`configs/schema/field_categories.json`);
- os tipos da baseline (`metrics/common/io.py`, `_BASELINE_EXPECTED_TYPES`);
- o normalizador pós-LLM (`src/mulitaminer/llm/llm_processing.py`).

**Prova concreta do drift:** o `schema_check` validava `plugin` como `str|None`, mas o
prompt do Tenable manda o LLM emitir um **número** — então todo registro Tenable correto
era marcado como erro de tipo. Idem `cvss` (o Tenable emite lista de strings; o validador
só aceitava número).

---

## 2. A solução: um model Pydantic

[`src/mulitaminer/configs/vuln_schema.py`](../../src/mulitaminer/configs/vuln_schema.py) é a
**fonte única**. Dele derivam (ou contra ele são vigiados):

| Consumidor | Como |
|---|---|
| `schema_check.py` | deriva os tipos via `validation_types()` / `expected_fields()` |
| `llm_processing.py` | deriva o mesmo mapa de campos/tipos |
| `field_categories.json` | **vigiado** por teste (não deriva — categorização é concern de métrica) |
| prompts (×2) | **vigiados** por teste (mantidos à mão — ver §4) |

Estrutura: uma base `VulnRecord` com os campos comuns; subclasses `OpenVASRecord` /
`TenableRecord` que **refinam o tipo** do que cada scanner realmente popula (Tenable:
`cvss` vira lista, `plugin_details` vira objeto estruturado, `instances` vira lista tipada).
Dispatch por `source` via `_BY_SOURCE`.

Resultado: o drift `plugin`/`cvss` sumiu, `schema_check` continua idêntico à referência nas
baselines OpenVAS, e mudar um campo é mexer em **um** lugar.

---

## 3. Extensibilidade (adicionar scanner)

A subclasse é a **menor peça, e é opcional** — se o scanner usa só os campos padrão, cai na
base sem escrever nada. Só declara subclasse quem tem campo próprio tipado. O grosso de
adicionar scanner (prompt + config de chunking) é inalterado. Ver
[`docs/EXTENSIBILITY.md`](../../docs/EXTENSIBILITY.md).

> Em aberto: se um dia for preciso deixar não-programadores adicionarem campos sem tocar em
> Python, dá pra declarar os campos num JSON e montar o model com `pydantic.create_model`
> (~40 linhas de leitor). Não feito agora (YAGNI — sem demanda comprovada). Preferência
> registrada do usuário: JSON, se/quando entrar.

---

## 4. Decisão: os prompts são VIGIADOS, não GERADOS

A ideia tentadora era **gerar** a linha de schema do prompt a partir do model (auto-sync,
zero drift). Testamos de verdade, via API do DeepSeek, num relatório OpenVAS (`bBWA`),
controle (prompt atual) vs variante (prompt gerado). **Custou ~US$2,3.**

**Resultado: gerar PIORA a extração.**

| Métrica | Controle | Variante (gerado) |
|---|---|---|
| vulns / schema conformance | 53 / 1.0 | 53 / 1.0 (empate) |
| BERTScore conteúdo (média) | 0.915 | 0.890 (**−0.025**) |
| **`port` nulo** | **0/53** | **32/53** |
| **`protocol` nulo** | **0/53** | **31/53** |

Causa: gerar o bloco na **ordem dos campos do model** quebrou o agrupamento do prompt à mão
(`cvss`/`port`/`protocol`/`severity` ficavam juntos porque saem da mesma região do
cabeçalho `High 443/tcp` / `High (CVSS: 7.5)`). Espalhados, o modelo passou a largar
`port`/`protocol` em ~60% dos casos.

**Lição:** a ordem/wording do prompt escrito à mão carrega conhecimento não-documentado que
importa. Regenerar mecanicamente destrói isso. Então mantemos os prompts à mão e usamos um
**teste-guarda** ([`tests/unit/test_schema_single_source.py`](../../tests/unit/test_schema_single_source.py)):
ele afirma que todo campo do model aparece no bloco de schema de cada prompt — pega drift
("adicionou campo no model, esqueceu o prompt") sem tocar no texto. Mesma filosofia do
`field_categories`: **vigiar em vez de gerar** quando o artefato é melhor mantido à mão.

Os artefatos do experimento (`openvas_prompt_genschema.txt`, `openvas_genschema.json`) foram
removidos. As saídas ficaram em `outputs/exp_control/` e `outputs/exp_variant/` para
referência.

---

## 5. Achado em aberto: validador de registro é código morto

Durante o experimento, descobri que `validate_and_normalize_vulnerability`
([`llm_processing.py`](../../src/mulitaminer/llm/llm_processing.py)) está **registrado**
(`profile_registry.py`) e documentado como "usado pelo main.py", mas **nenhuma parte do
pipeline de extração o chama**. O `save_results` escreve a saída do LLM direto, sem
normalização por registro.

- **Impacto hoje:** nenhum com modelo forte (DeepSeek-v4 devolve registros completos e
  limpos). Modelos fracos (gemma4/mistral) que malformem a saída ficam **sem rede de
  segurança** (coerção de tipo, descarte de nome-lixo, `INFO→LOG`).
- **Por que não consertei aqui:** ligar o validador afeta **todos** os scanners e ativa
  comportamento (descarte de registros) que precisa de teste amplo. É conserto legítimo,
  mas deliberado e à parte — não no meio da consolidação do schema.
- Verificado que, se ligado, é **no-op** nos 53 registros do controle (0 mudaram) — então
  o risco é baixo, mas ainda assim merece sua própria PR + testes.
