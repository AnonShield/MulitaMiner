# Padrões de Saída e Interoperabilidade — MulitaMiner

Documento de análise: quais padrões de saída o ecossistema de vulnerabilidades usa
além do CycloneDX VEX, qual faz sentido o Mulita adotar, e como demonstrar que a
saída estruturada ajuda ferramentas downstream mais que o PDF cru.

Complementa o [`SCHEMA_PROPOSAL.md`](SCHEMA_PROPOSAL.md) (schema híbrido interno) e a
[`docs/PRIORITIZATION.md`](../../docs/PRIORITIZATION.md) (camada SSVC + EPSS + KEV).

---

## 1. Vocabulário ≠ envelope

Distinção que orienta toda a escolha de padrão:

- **Vocabulário** = o que os campos *significam* (CVE, CPE, CWE, CVSS). Domínio do
  **NIST/MITRE/FIRST**. O Mulita **já usa** esse vocabulário.
- **Envelope de troca** = o *formato do arquivo* que empacota os findings. Domínio de
  **OASIS** (CSAF, SARIF, STIX) e **OWASP** (CycloneDX). É aqui que se escolhe "formato
  de saída".

Consequência prática: adotar um "padrão de saída" é escolher um **envelope**, não trocar
o vocabulário — que já está certo.

---

## 2. O mundo "NIST" — o que é e o que não serve

O NIST **não define um formato moderno de relatório de findings para priorização**. O que
ele mantém é o **SCAP** (Security Content Automation Protocol), um guarda-chuva:

| Componente SCAP | O que é | Serve de saída p/ Mulita? |
|---|---|---|
| CVE / CPE / CWE / CVSS | Vocabulários (identificadores e scores) | Já usados como vocabulário |
| **OVAL** | Linguagem de checagem de estado (XML) | Não — é *como checar*, não resultado de scan |
| **XCCDF** | Checklist de configuração/hardening | Não — compliance, não vulnerabilidade |
| **ARF** (Asset Reporting Format) | Envelope de *resultados* de assessment (XML) | O único candidato NIST-nativo, mas **XML pesado, orientado a compliance** — nenhuma ferramenta de priorização moderna pede ARF |

**Veredito:** o ângulo "NIST" se resolve **usando o vocabulário** (CVE/CWE/CVSS, que o Mulita
já faz), **não** adotando ARF/OVAL como envelope. O `CVE Record Format 5.x` (CNA JSON, hoje
sob CVE.org/MITRE) é a fonte autoritativa de dados de CVE, mas é feed de *dados*, não formato
de *relatório de scan*.

---

## 3. Envelopes que valem a pena, por caso de uso

| Padrão | Dono | Bom para | Relevância |
|---|---|---|---|
| **CSAF 2.0** (+ perfil VEX) | OASIS | Advisories machine-readable; padrão do mundo **CSIRT/governo** (CISA publica em CSAF; Red Hat, Cisco, Siemens, Oracle) | **Alta** |
| **SARIF 2.1.0** | OASIS | **Ingestão de findings por outras ferramentas** (GitHub code scanning, DefectDojo, IDEs) | **Alta** |
| **OCSF** — Vulnerability Finding | AWS/Splunk et al. | Alimentar **SIEM / data lake** de segurança | Média |
| **STIX 2.1** | OASIS | Threat intel sharing (CTI) | Baixa |
| **CycloneDX VEX** | OWASP | Supply chain / SBOM | Já analisado; modelo de *componente*, não de *host:porta* |

### Por que CSAF e SARIF na frente

- **CSAF 2.0/VEX** — sucessor do CVRF, JSON, **endossado pela CISA**. Tem
  `remediations[].category` (enum: `mitigation`, `vendor_fix`, `workaround`,
  `no_fix_planned`, `none_available`) que casa **1:1 com a decisão `remediation.type`** do
  schema híbrido. É o argumento de interoperabilidade mais forte para banca, e o mais próximo
  do mundo NIST/gov/CSIRT. Também carrega `product_tree` e `vulnerabilities[].scores[]`
  (CVSS múltiplos) alinhados ao `ratings[]` do híbrido.
- **SARIF** — é o *de facto* de "resultado de scanner" que ferramentas **realmente consomem**.
  Foi desenhado para análise estática, mas o modelo (`runs[].results[]` com `ruleId`,
  `level`, `locations[]`) mapeia bem findings de scan. É o convite de entrada para
  automação downstream.

CycloneDX VEX fica em terceiro: bom pro ângulo SBOM, mas é o que menos casa com scanner de rede.

### Quem consome esses formatos (a tese de "ajudar outras ferramentas")

Plataformas de gestão de vulnerabilidade que ingerem formatos estruturados e fazem
dedup/priorização/tracking entre scanners:

O que **cada plataforma-alvo realmente ingere** (verificado, jul/2026):

| Plataforma | Tipo | Ingere nativamente | Não ingere |
|---|---|---|---|
| **DefectDojo** — maior agregador de findings, o match mais próximo do Mulita | Agregador de scan | **SARIF**, **CycloneDX**, Generic (JSON/CSV), Universal Pro (JSON/CSV/XML) | **CSAF** (só via Universal, forçando o JSON) |
| **OWASP Dependency-Track** | SBOM / supply-chain | **CycloneDX** (SBOM + VEX) | SARIF |
| **SecObserve, Trustification, CSAF Walker** | Advisory / PSIRT | **CSAF VEX** | (não são agregadores de scan) |
| **GitHub Code Scanning, SonarQube, Jenkins, Azure DevOps, VS Code** | Ecossistema SAST | **SARIF** | — |

Fontes: [DefectDojo — SARIF](https://docs.defectdojo.com/supported_tools/parsers/file/sarif/) ·
[DefectDojo — CycloneDX](https://docs.defectdojo.com/supported_tools/parsers/file/cyclonedx/) ·
[DefectDojo — Universal Parser](https://docs.defectdojo.com/import_data/pro/specialized_import/universal_parser/) ·
[DefectDojo — Generic Findings Import](https://docs.defectdojo.com/supported_tools/parsers/file/generic/) ·
[Dependency-Track docs](https://docs.dependencytrack.org/) ·
[csaf.io/tools](https://www.csaf.io/tools/) ·
[GitHub — SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)

**Dois mundos de consumo — não confundir:**

1. **Agregador de findings de scanner** (DefectDojo e cia). É onde o Mulita se encaixa, porque
   o Mulita *é fonte de findings*. Formato ingerido nativamente: **SARIF** (+ CycloneDX pro
   lado SBOM). **CSAF não é ingerido pelo DefectDojo.**
2. **Distribuição de advisory / PSIRT** (CISA, SecObserve, Trustification). É quem consome
   **CSAF** — fluxo de *publicar boletim de um produto*, não de *jogar findings de um scan pra
   priorizar*. O Mulita não publica advisory; ele extrai findings de scan.

Nenhum desses ingere PDF de primeira classe (Seção 5.1) — esse é o gancho do experimento da Seção 5.

---

## 4. Recomendação de arquitetura de saída

Manter o **schema híbrido como canônico interno** (decisão do `SCHEMA_PROPOSAL.md` está
certa) e adicionar conversores em camada de exportação. **A ordem abaixo foi reancorada em
consumidor real** (Seção 3) — inverteu a intuição inicial de "CSAF primeiro por causa da banca",
porque CSAF é formato de *publicador de advisory*, não o que um agregador de scan ingere:

1. **Generic/CSV-JSON (fallback pragmático)** — o `Generic Findings Import` do DefectDojo aceita
   **JSON/CSV**, e o Mulita **já emite o CSV de priorização**. É a primeira integração real com
   esforço quase zero — provar o fluxo antes de investir em formato rico.
2. **SARIF** — ingerido nativamente pelo DefectDojo (o consumidor mais próximo do caso Mulita) e
   por todo o ecossistema GitHub/SonarQube/Jenkins/Azure. É o "ajudar outras ferramentas"
   concreto e verificável, **hoje**. Melhor entrada estruturada do A/B da Seção 5.
3. **CSAF 2.0/VEX** — valioso, mas por *outro* motivo: **alinhamento com padrão gov/CISA** no
   paper, não "plataforma X ingere". Honesto declarar isso: consumido por SecObserve/
   Trustification (advisory), não pelo DefectDojo.
4. **CycloneDX VEX** — só compensa se o alvo for Dependency-Track / mundo SBOM. Mismatch com
   scan de rede (modelo de *componente*, não *host:porta*).

Nada disso muda o pipeline de extração — é camada de saída, via
`--output-format {mulita-legacy | hybrid | generic | sarif | csaf | cyclonedx-vex}`.

---

## 5. Experimento: saída estruturada vs. PDF cru

### 5.1 Enquadramento forte: PDF não é formato de ingestão de primeira classe

O argumento mais forte **não** é "ajuda mais" — é **categórico**: as plataformas de gestão/
agregação de vulnerabilidade padronizam a importação em **XML/JSON/CSV**, e o PDF **não é
formato de ingestão de primeira classe** nelas. A saída estruturada do Mulita não é 10%
melhor; é a diferença entre *automatizável* e *dead-end para automação*.

Evidência (verificada, jul/2026):

- **DefectDojo** (maior agregador open-source, 200+ parsers): importa JSON/XML/CSV; o
  Universal Parser aceita JSON e CSV. **PDF não aparece como formato de importação.**
  [docs.defectdojo.com/supported_tools](https://docs.defectdojo.com/supported_tools/)
- **NamicSoft, ArcherySec, VulnRepo**: importam via **XML** exportado do Nessus/OpenVAS.
  [namicsoft.com](https://www.namicsoft.com/)
- **Greenbone/OpenVAS** e **Tenable/Nessus** documentam o PDF como saída *para humano ler*
  e indicam o **XML nativo** para importação (preserva todos os dados).
  [docs.greenbone.net](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html) ·
  [docs.tenable.com](https://docs.tenable.com/nessus/Content/ExportAScan.htm)

> **Calibração honesta:** *não* dá para afirmar "nenhuma ferramenta ingere PDF" — é um
> negativo universal improvável de provar, e existe uma categoria inteira de ferramentas
> cujo trabalho é justamente extrair findings de PDF (o **próprio Mulita**, OCR, ingestão
> via LLM, alguns GRC comerciais). O ponto sustentável é o mais fraco e mais defensável:
> PDF não é cidadão de primeira classe no pipeline de ingestão dessas plataformas — e é
> exatamente essa lacuna que o Mulita preenche, virando a ponte PDF → XML/JSON/SARIF/CSAF.

### 5.2 Enquadramento mensurável: A/B na priorização

Para o eixo "ajuda mais na priorização", um A/B reaproveitando a camada que já existe:

Alimentar um **consumidor downstream** (ex.: um LLM instruído *"priorize estes findings,
o que corrijo primeiro?"*) de dois jeitos:

- **(A)** o **PDF cru** do scanner;
- **(B)** a **saída estruturada** do Mulita (JSON híbrido, ou já exportada SARIF/CSAF).

Medir contra o **ranking SSVC determinístico do próprio Mulita como referência**.

Eixos onde (B) deve ganhar, e como medir:

| Eixo | Por que (B) ganha | Métrica |
|---|---|---|
| **Completude** | No PDF de 200 findings o consumidor esquece findings enterrados; no estruturado todos são enumerados | nº de findings recuperados / total |
| **Consistência** | Priorização a partir do PDF varia entre execuções; do estruturado é estável | variância do ranking em N rodadas |
| **Aterramento** | CVE-ID sai limpo do estruturado → lookup EPSS/KEV correto; extrair CVE de PDF erra → sinal errado | acurácia de CVE extraído; correção do sinal de exploração vs. referência |

### 5.3 Por que é barato

Não é ferramenta nova pesada — é experimento comparativo que reaproveita `tools/backtest.py`
e a priorização SSVC já existentes. Fecha a narrativa: **extrair → estruturar → priorizar →
interoperar**.

---

## 6. Decisões em aberto

- [ ] Ordem de implementação dos conversores (recomendado: CSAF → SARIF → CycloneDX).
- [ ] Consumidor downstream do A/B: LLM-assistente vs. ingestão real em DefectDojo (ou ambos).
- [ ] Perfil CSAF a mirar: `csaf_vex` (mais enxuto) vs. `csaf_security_advisory` (completo).
- [ ] Mapear campos `scanner_specific` do híbrido: em CSAF vão para `notes[]`; em SARIF para
      `properties` (property bag). Confirmar que nada crítico se perde.
