<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="imgs/MulitaMiner_logo_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="imgs/MulitaMiner_logo_light.png">
    <img src="imgs/MulitaMiner_logo_light.png" width="420" alt="MulitaMiner logo">
  </picture>

**Vulnerability Extraction from Security Reports using LLMs**

</div>

---

# ⚠️ Avaliadores de artefatos: escolha a branch correta

Este repositório hospeda **artefatos de artigos diferentes**, cada um em sua própria
branch. Esta branch (`main`) **não é um artefato de avaliação** e serve apenas como
índice.

> **Reviewers:** this repository hosts the artifacts of **different papers**, each on its
> own branch. This branch (`main`) is **not** an evaluation artifact, it is only an index.
> Pick the row matching the paper you are reviewing.

| Artigo / Paper | Branch | Abrir artefato |
| -------------- | ------ | -------------- |
| **SBSeg 2026 · Trilha Principal**<br>*MulitaMiner: A Multi-Version Evaluation of LLM-Based Vulnerability Report Extraction*<br><sub>Progressão do pipeline V1 → V2 → V3, avaliada com **LLMs em nuvem** (450 execuções).</sub> | [`V3`](../../tree/V3) | **[▶ Abrir / Open](../../tree/V3)** |
| **WTICG 2026**<br>*On-Premise vs. Cloud: Local LLMs for Vulnerability Extraction from Security Scanner Reports*<br><sub>Nove **modelos locais** (4B a 21B) comparados a uma referência DeepSeek em nuvem.</sub> | [`slms`](../../tree/slms) | **[▶ Abrir / Open](../../tree/slms)** |

Os dois artigos tratam de extração de vulnerabilidades com LLMs, mas são trabalhos
distintos: o do **SBSeg** mede o efeito da **engenharia do pipeline** usando modelos em
nuvem; o do **WTICG** mede o custo em qualidade de rodar **modelos locais** para preservar
a confidencialidade dos relatórios. Confira o título antes de começar a avaliação.

Cada branch traz seu próprio `README.md` completo, com selos considerados, informações
básicas, dependências, instalação, teste mínimo e as reivindicações do respectivo artigo.

## Material anterior

| Conteúdo | Referência |
| -------- | ---------- |
| Artefato da versão anterior da ferramenta (dataset de 6.700 vulnerabilidades extraídas de 129 relatórios OpenVAS), publicado no Zenodo | [`v2-dataset-artifact`](../../tree/v2-dataset-artifact) |

Essa tag preserva o estado desta branch antes de ela se tornar um índice, para que
referências já publicadas continuem válidas.

## Sobre a ferramenta

**MulitaMiner** é uma ferramenta automatizada para extrair e estruturar vulnerabilidades a
partir de relatórios PDF heterogêneos produzidos por scanners de segurança (OpenVAS,
Tenable WAS). Seu pipeline baseado em LLMs combina segmentação adaptativa por scanner e
prompts especializados para converter achados não estruturados em registros consistentes e
prontos para análise, com saídas padronizadas e validação de qualidade.

## LICENSE

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).
