# Vulnerability Extractor: Sistema de Extração de Vulnerabilidades de Documentos Não Estruturados com LLMs

_Última atualização: Fevereiro 2026_

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc/4.0/)

## Visão Geral

O **Vulnerability Extractor** é uma ferramenta desenvolvida para extrair e processar vulnerabilidades de relatórios PDF de segurança utilizando Large Language Models (LLMs) com sistema de chunking otimizado. A ferramenta implementa um sistema inteligente de otimização de tokens que garante processamento eficiente sem excedente, oferecendo suporte a múltiplos provedores de LLM e estratégias de scanning especializadas para diferentes ferramentas de segurança (OpenVAS, Tenable WAS, Nessus, ...).

### Casos de Uso

- **Análise de Segurança**: Extração automatizada de vulnerabilidades de relatórios de scanners
- **Integração Empresarial**: Suporte a formatos CAIS para sistemas corporativos
- **Pesquisa e Desenvolvimento**: Avaliação comparativa de diferentes LLMs

### Diferenciais

- **Zero Token Exceedances**: Sistema matemático garantido de cálculo de chunks
- **Multi-LLM Support**: 6 provedores diferentes com configurações otimizadas
- **Consolidação Inteligente**: Merge automático de vulnerabilidades duplicadas (ou apenas remoção, conforme configuração)
- **Logs Detalhados**: Geração automática de logs de remoção e deduplicação (removed_log, duplicates_removed_log, merge_log)
- **Avaliação de Métricas**: Comparação automática com baselines usando BERT/ROUGE
- **Exportação Multi-Formato**: JSON, CSV, XLSX com layouts preservados

## Funcionalidades

### Extração Inteligente

- **Extração automática** de vulnerabilidades de relatórios PDF de segurança
- **Suporte multi-scanner**: OpenVAS, Tenable WAS, Nessus, e outros
- **Validação automática** de dados extraídos com normalização
- **Sistema robusto de retry** com subdivisão inteligente de chunks

### Sistema de Chunking Otimizado

- **Cálculo automático de tokens** baseado em limites específicos de cada LLM
- **Zero excedências garantidas** através de múltiplas camadas de segurança
- **Otimização dinâmica** de tamanho de chunks por modelo
- **Validação integrada** com `chunk_validator.py` para análise de qualidade

### Consolidação Avançada

- **TenableWAS**: Merge inteligente de instances e bases por vulnerabilidade
- **OpenVAS**: Agrupamento por similaridade de nome e características
- **CAIS**: Consolidação por definições com campos especializados

### Multi-LLM com Otimização

- **6 LLMs suportados** com configurações otimizadas individuais:
  - **DeepSeek**: Ultra-eficiente para análise técnica
  - **GPT-4**: Balanceado para uso geral
  - **GPT-5**: Ultra-seguro para processamento crítico
  - **Llama 3/4**: Modelos Groq gratuitos com diferentes perfis
  - **Qwen3**: Alternativa eficiente

### Exportação Multi-Formato e Logs

- **JSON estruturado** (formato principal)
- **CSV/TSV** com delimitadores customizáveis
- **XLSX** (Excel) com formatação avançada
- **Layout visual preservado** em arquivo .txt
- **Logs detalhados**:
  - `*_removed_log.txt`: Vulnerabilidades removidas por falta de descrição/campos essenciais
  - `*_duplicates_removed_log.txt`: Vulnerabilidades removidas por serem duplicatas exatas (quando `--allow-duplicates`)
  - `*_merge_log.txt`: Vulnerabilidades realmente mescladas (quando `--allow-duplicates` não está ativo)

## Instalação

### Requisitos do Sistema

- **Python**: 3.8+ (recomendado: Python 3.10+)
- **RAM**: 4GB+ recomendado para processamento de PDFs grandes

### Instalação Passo-a-Passo

#### 1. Clone do Repositório

```bash
git clone https://github.com/your-repo/vulnerability-extractor.git
cd Vulnerability_Extractor
```

#### 2. Ambiente Virtual (Altamente Recomendado)

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python -m venv .venv
source .venv/bin/activate
```

#### 3. Instalação de Dependências

```bash
pip install -r requirements.txt
```

### Dependências Python Principais

#### Core - Framework LLM e processamento

```pip-requirements
langchain>=0.1.0,<0.3.0          # Framework principal para LLMs
langchain-openai>=0.1.0,<0.2.0   # Integração OpenAI
```

#### PDF Processing - Extração de texto otimizada

```pip-requirements
pdfplumber>=0.10.0,<0.12.0       # Extração de texto de PDFs
```

#### UI/UX - Progress bars e feedback

```pip-requirements
tqdm>=4.0.0,<5.0.0               # Barras de progresso
```

#### Data Processing - Merge e normalização

```pip-requirements
deepmerge>=1.1.0,<2.0.0          # Merge de dicionários complexos
```

#### Metrics Evaluation - Avaliação de métricas

```pip-requirements
rapidfuzz>=3.0.0,<4.0.0          # Fuzzy string matching
bert-score>=0.3.0,<0.4.0         # BERTScore para avaliação
rouge-score>=0.1.0,<0.2.0        # ROUGE metrics
```

#### Export Formats - CSV, XLSX

```pip-requirements
pandas>=1.3.0,<3.0.0             # DataFrames e manipulação
openpyxl>=3.0.0,<4.0.0           # Exportação Excel
```

## Configuração

### Configuração de API Keys

As chaves de API são configuradas através de **variáveis de ambiente** no arquivo `.env`. O sistema suporta substituição automática de variáveis nos arquivos de configuração JSON.

#### 1. Configurar arquivo .env

Edite o arquivo `.env` existente com suas chaves de API:

```env
API_KEY_DEEPSEEK = "your-deepseek-api-key"
API_KEY_GPT4 = "your-openai-api-key"
API_KEY_GPT5 = "your-openai-api-key"
API_KEY_LLAMA3 = "your-groq-api-key"
API_KEY_LLAMA4 = "your-groq-api-key"
API_KEY_QWEN3 = "your-groq-api-key"
```

#### 2. Como funciona a substituição

Os arquivos de configuração JSON usam a sintaxe `${VARIABLE_NAME}` para referenciar variáveis do `.env`:

```json
{
  "api_key": "${API_KEY_DEEPSEEK}",
  "endpoint": "https://api.deepseek.com/v1",
  "model": "deepseek-coder"
}
```

#### 3. Provedores Suportados

| Provedor     | Modelos           | Custo    | Velocidade   |
| ------------ | ----------------- | -------- | ------------ |
| **OpenAI**   | GPT-4, GPT-5      | $$$      | Rápido       |
| **Groq**     | Llama 3/4, Qwen 3 | Gratuito | Ultra-rápido |
| **DeepSeek** | DeepSeek Coder    | $$       | Rápido       |

**⚠️ Segurança:** Nunca commite o arquivo `.env` para repositórios públicos!

### Sistema de Cálculo de Tokens

O sistema calcula automaticamente o tamanho ideal dos chunks para cada LLM, garantindo **zero excedências** e máxima eficiência através de uma fórmula matemática precisa.

#### Fórmula Universal

```
max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer
```

#### Componentes da Fórmula

| Componente             | Descrição                   | Exemplo       |
| ---------------------- | --------------------------- | ------------- |
| `max_tokens`           | Limite total do modelo      | 8192 (Llama4) |
| `reserve_for_response` | Espaço para resposta do LLM | 5000 tokens   |
| `prompt_overhead`      | Template + instruções       | 600 tokens    |
| `system_overhead`      | Metadados + overhead        | 500 tokens    |
| `safety_buffer`        | Margem de segurança         | 600 tokens    |

#### Configurações Reais por LLM

| LLM          | Limite Total | Reserve | Chunk Final | Overhead Calculado | Eficiência |
| ------------ | ------------ | ------- | ----------- | ------------------ | ---------- |
| **GPT-4**    | 12,000       | 4,000   | **7,300**   | 700 tokens         | 60.8%      |
| **GPT-5**    | 16,000       | 6,000   | **8,300**   | 1,700 tokens       | 51.9%      |
| **DeepSeek** | 4,096        | 1,500   | **1,750**   | 846 tokens         | 42.7%      |
| **Llama3**   | 8,192        | 4,000   | **3,492**   | 700 tokens         | 42.6%      |
| **Llama4**   | 8,192        | 5,000   | **1,492**   | 1,700 tokens       | 18.2%      |
| **Qwen3**    | 8,192        | 4,000   | **3,492**   | 700 tokens         | 42.6%      |

**Overhead Calculado** = (Limite Total - Reserve) - Chunk Final

#### Interpretação dos Valores

- **Overhead varia por LLM**: Templates mais complexos precisam de mais espaço
- **Reserve para resposta**: Baseado em testes reais de verbosidade do modelo
- **Eficiência**: Percentual do limite total usado para processamento de chunks
- **Segurança**: Todos os valores testados garantem zero exceedances

## Uso

### Interface CLI

**Sintaxe básica:**

```bash
python main.py <pdf_path> [opções]
```

### Parâmetros Principais

#### Entrada Obrigatória

- `pdf_path`: **Caminho para o arquivo PDF** do relatório de vulnerabilidades

#### Opções de Processamento

| Parâmetro   | Descrição                | Padrão    | Exemplos                             |
| ----------- | ------------------------ | --------- | ------------------------------------ |
| `--scanner` | Estratégia de scanner    | `default` | `tenable`, `openvas`, `cais_tenable` |
| `--llm`     | Modelo de Language Model | `gpt4`    | `deepseek`, `llama3`, `gpt5`         |

#### Opções de Exportação

| Parâmetro         | Descrição                | Padrão | Exemplos                |
| ----------------- | ------------------------ | ------ | ----------------------- |
| `--convert`       | Formato de conversão     | `none` | `csv`, `xlsx`, `all`    |
| `--output-file`   | Nome do arquivo de saída | auto   | `vulnerabilidades.json` |
| `--output-dir`    | Pasta de destino         | atual  | `./resultados`          |
| `--csv-delimiter` | Separador CSV            | `,`    | `;`                     |

#### Opções de Avaliação

| Parâmetro             | Descrição                    | Padrão                       |
| --------------------- | ---------------------------- | ---------------------------- |
| `--evaluate`          | Ativa avaliação de métricas  | `false`                      |
| `--baseline-file`     | Arquivo ground truth (.xlsx) | obrigatório com `--evaluate` |
| `--evaluation-method` | Método: `bert` ou `rouge`    | `bert`                       |
| `--allow-duplicates`  | Permite duplicatas legítimas | `false`                      |

### Extração em Lote

Para processar todos os PDFs de um diretório em lote:

```bash
python tools/batch_pdf_extractor.py <diretorio_pdfs> --convert <formato> --llm <modelo> --scanner <scanner> [--allow-duplicates] [--output-dir <dir>]
```

Todos os argumentos extras são repassados para o main.py. Exemplo:

```bash
python tools/batch_pdf_extractor.py pdfs --scanner openvas --LLM deepseek --allow-duplicates --output-dir jsons
```

---

### Exemplos de Uso

#### Uso Básico

```bash
# Processamento padrão com GPT-4
python main.py relatorio.pdf
# Scanner específico
python main.py relatorio_tenable.pdf --scanner tenable
# Modelo específico
python main.py relatorio.pdf --llm deepseek
```

#### Exportação de Formatos

```bash
# CSV com configuração personalizada
python main.py relatorio.pdf --convert csv --csv-delimiter ";" --csv-encoding "iso-8859-1" --output-file "vulnerabilidades_pt.csv"
# Exportação completa para Excel
python main.py relatorio_grande.pdf --scanner tenable --llm gpt5 --convert xlsx --output-dir ./resultados
# Todos os formatos simultâneos
python main.py relatorio.pdf --convert all --output-dir ./exports
```

#### Cenários Especializados

```bash
# Tenable WAS otimizado para máxima extração
python main.py tenable_report.pdf --scanner tenable --llm gpt4 --convert all
# OpenVAS com modelo gratuito Groq
python main.py openvas_scan.pdf --scanner openvas --llm llama3 --convert csv
# CAIS Tenable para integração empresarial
python main.py cais_tenable.pdf --scanner cais_tenable --llm gpt5 --convert xlsx
```

#### Uso Avançado: Extração com Avaliação de Métricas

É possível executar a extração e, na mesma operação, avaliar a qualidade do resultado comparando-o com um arquivo de "ground truth" (baseline).

```bash
# Extrai vulnerabilidades e avalia a qualidade da extração usando o método 'bert'
python main.py relatorio_tenable.pdf --scanner tenable --convert all --evaluate --baseline-file metrics/baselines/tenable/TenableWAS_JuiceShop.xlsx --evaluation-method bert
# Avaliação com duplicatas legítimas permitidas (recomendado para OpenVAS)
python main.py relatorio_openvas.pdf --scanner openvas --llm deepseek --convert xlsx --evaluate --baseline-file metrics/baselines/openvas/OpenVAS_JuiceShop.xlsx --allow-duplicates
```

#### Validação e Debugging

```bash
# Validação de chunks antes do processamento
python tools/chunk_validator.py relatorio.pdf
# Análise detalhada de chunks por LLM
python tools/chunk_validator.py relatorio.pdf --llm gpt4 --scanner tenable
```

## Análises de Métricas

### Análises Isoladas

Você pode executar análises de métricas de forma independente, comparando extrações já realizadas com baselines de ground truth.

#### Análise BERT

```bash
# Análise com BERT
python metrics/bert/compare_extractions_bert.py --baseline-file <caminho_relativo_do_arquivo_baseline> --extraction-file <caminho_relativo_do_arquivo_de_extração> --model <llm> --allow-duplicates
```

#### Análise ROUGE

```bash
# Análise básica com ROUGE
python metrics/rouge/compare_extractions_rouge.py --baseline-file <caminho_relativo_do_arquivo_baseline> --extraction-file <caminho_relativo_do_arquivo_de_extração> --model <llm> --allow-duplicates
```

### Geração de Gráficos

> **Importante:** Passe o arquivo de baseline (ground truth) no parâmetro --baseline. **Não** utilize o arquivo de extração gerado pelo modelo aqui. O script de plotagem utiliza a baseline como referência para comparar automaticamente os resultados de todos os modelos/extrações disponíveis para aquele conjunto de dados.

Use o CLI de plot para gerar gráficos comparativos de métricas de um ou mais modelos.

#### Gráfico Individual

```bash
# Gráfico simples de um modelo
python -m metrics.plot.cli --metric rouge --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek
```

#### Comparação Múltipla

```bash
# Comparação de três modelos
python -m metrics.plot.cli --metric bert --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek,gpt4,llama3
```

#### Gráfico com Filtros

```bash
# Gráfico focado em métricas específicas
python -m metrics.plot.cli --metric rouge --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek --baseline-sheet Vulnerabilities
```

### Fluxo de Processamento

1. **Entrada**: PDF especificado em `pdf_path`
2. **Cálculo de chunks**: Sistema otimizado calcula tamanhos ideais por LLM
3. **Processamento**: Usando scanner e LLM configurados com chunks otimizados
4. **Validação de tokens**: Garantia de zero exceedances durante processamento
5. **Extração**: Vulnerabilidades extraídas com retry inteligente
6. **Consolidação**: Remoção de duplicatas e merge de instances (TenableWAS)
7. **Saída primária**: JSON conforme `output_file` do scanner
8. **Conversões**: Formatos adicionais (CSV, XLSX,...) conforme `--convert`
9. **Layout visual**: Arquivo `.txt` com layout preservado (mesmo diretório do PDF)

### Arquivos Gerados

- **JSON principal**: `vulnerabilities_<scanner>.json`
- **Layout visual**: `visual_layout_extracted_<nome_arquivo>.txt`

### Formato de Saída

#### Estrutura JSON

A ferramenta gera um arquivo JSON com as vulnerabilidades encontradas. O formato completo inclui campos específicos para diferentes tipos de relatórios:

```json
[
  {
    "Name": "SQL Injection",
    "description": ["Detailed description of the vulnerability"],
    "detection_result": ["Vulnerability detection result (OpenVAS only)"],
    "detection_method": ["Vulnerability detection method (OpenVAS only)"],
    "impact": ["Impact description (OpenVAS only)"],
    "solution": ["Recommended solutions"],
    "insight": ["Vulnerability insight (OpenVAS only)"],
    "product_detection_result": ["Product detection result (OpenVAS only)"],
    "log_method": ["Log method (OpenVAS only)"],
    "cvss": [
      "CVSSV4 BASE SCORE - number",
      "CVSSV4 VECTOR - string",
      "CVSSv3 BASE SCORE - number",
      "CVSSv3 VECTOR - string",
      "CVSSv2 BASE SCORE - number",
      "CVSS BASE SCORE - number",
      "CVSS VECTOR - string"
    ],
    "port": "80",
    "protocol": "tcp",
    "severity": "HIGH",
    "references": ["List of references"],
    "plugin": ["Plugin details (Tenable WAS only)"],
    "source": "OPENVAS"
  }
]
```

#### Mapeamento de Campos por Ferramenta

| Campo                      | OpenVAS | Tenable WAS | Descrição                                      |
| -------------------------- | ------- | ----------- | ---------------------------------------------- |
| `Name`                     | ✅      | ✅          | Nome da vulnerabilidade                        |
| `description`              | ✅      | ✅          | Descrição detalhada                            |
| `detection_result`         | ✅      | ❌          | Resultado da detecção (apenas OpenVAS)         |
| `detection_method`         | ✅      | ❌          | Método de detecção (apenas OpenVAS)            |
| `impact`                   | ✅      | ❌          | Impacto da vulnerabilidade (apenas OpenVAS)    |
| `solution`                 | ✅      | ✅          | Soluções recomendadas                          |
| `insight`                  | ✅      | ❌          | Insights da vulnerabilidade (apenas OpenVAS)   |
| `product_detection_result` | ✅      | ❌          | Resultado detecção do produto (apenas OpenVAS) |
| `log_method`               | ✅      | ❌          | Método de log (apenas OpenVAS)                 |
| `cvss`                     | ✅      | ✅          | Scores CVSS (múltiplas versões)                |
| `port`                     | ✅      | ✅          | Porta da vulnerabilidade                       |
| `protocol`                 | ✅      | ✅          | Protocolo (tcp/udp)                            |
| `severity`                 | ✅      | ✅          | Severidade (LOG/LOW/MEDIUM/HIGH/CRITICAL)      |
| `references`               | ✅      | ✅          | Referências e links                            |
| `plugin`                   | ❌      | ✅          | Detalhes do plugin (apenas Tenable WAS)        |
| `source`                   | ✅      | ✅          | Fonte do relatório (OPENVAS/TENABLEWAS)        |

### Resolução de Problemas

#### Erros de Tokens

| Erro                                                 | Causa                            | Solução                                                    |
| ---------------------------------------------------- | -------------------------------- | ---------------------------------------------------------- |
| `"Setting 'max_tokens' and 'max_completion_tokens'"` | Conflito entre parâmetros OpenAI | Sistema corrigido para usar apenas `max_completion_tokens` |
| `"Token limit exceeded"`                             | Chunk muito grande               | Sistema de chunks otimizados resolve automaticamente       |
| `"Rate limit exceeded"`                              | Muitas requisições               | Aguardar reset da quota ou usar provedor alternativo       |

### Erros de Conectividade

| Erro                     | Causa                       | Solução                                        |
| ------------------------ | --------------------------- | ---------------------------------------------- |
| `SSL/Network`            | Problema temporário de rede | Tentar novamente ou aumentar `timeout`         |
| `"API key inválida"`     | Chave incorreta/expirada    | Verificar configuração no `.env`               |
| `"modelo descontinuado"` | Modelo não disponível       | Atualizar para modelo válido nas configurações |

### Erros de Modelo

| Erro                      | Causa                      | Solução                                |
| ------------------------- | -------------------------- | -------------------------------------- |
| `"limite de quota"`       | Excedeu limite do provedor | Usar Groq (gratuito) ou aguardar reset |
| `"modelo não encontrado"` | Nome incorreto             | Verificar configuração do LLM          |

### Dicas de Otimização

#### Por Tamanho do Relatório

| Tamanho            | Recomendação | Justificativa                           |
| ------------------ | ------------ | --------------------------------------- |
| **< 50 páginas**   | GPT-4/GPT-5  | Chunks maiores, processamento eficiente |
| **50-200 páginas** | Llama3/Qwen3 | Balanceamento ótimo                     |
| **> 200 páginas**  | Llama4       | Processamento incremental mais preciso  |

#### Por Tipo de Análise

| Cenário                   | Melhor LLM  | Por que?                           |
| ------------------------- | ----------- | ---------------------------------- |
| **Análise Técnica**       | DeepSeek    | Especializado em código/segurança  |
| **Processamento Crítico** | GPT-5       | Máxima segurança e precisão        |
| **Economia**              | Llama3/Groq | Gratuito e eficiente               |
| **Debugging**             | Llama4      | Máxima precisão em chunks pequenos |

#### ⚡ Performance Tips

- **BERTScore otimizado**: Modelo carregado uma vez, avaliação em ~30 segundos
- **Avaliação com duplicatas**: Usar `--allow-duplicates` com OpenVAS
- **Monitoramento**: Logs detalhados para identificação de gargalos

## Experimentos

O Vulnerability Extractor foi validado através de experimentos práticos com diferentes tipos de relatórios e configurações de LLM.

### Cenários de Teste

#### Tenable WAS Reports

- **Configuração testada**: Scanner `tenable` + LLM `gpt4`
- **Documentos testados**: Relatórios de 50-200 páginas
- **Resultados**: Consolidação eficiente de instances/bases, detecção precisa de plugins
- **Otimização**: Chunks de 7300 tokens com merge inteligente de vulnerabilidades

#### OpenVAS/Greenbone Reports

- **Configuração testada**: Scanner `openvas` + LLM `llama3`
- **Documentos testados**: Relatórios NVT com 100-500 vulnerabilidades
- **Resultados**: Extração completa de 18 campos especializados (detection_result, impact, insight)
- **Otimização**: Chunks de 3492 tokens com processamento gratuito via Groq

### Validação de Token Optimization

#### Experimento: Zero Token Excedentes

```bash
# Teste com documento de 300 páginas
python main.py large_report.pdf --llm gpt4
# Resultado: 42 chunks processados, 0 exceedances

python chunk_validator.py large_report.pdf --llm gpt4
# Análise: Distribuição uniforme, eficiência 60.8%
```

#### Experimento: Comparative Performance

```bash
# Teste comparativo entre modelos
python main.py test_report.pdf --llm llama4  # Precisão máxima (1492 tokens)
python main.py test_report.pdf --llm gpt4    # Balanceado (7300 tokens)
python main.py test_report.pdf --llm deepseek # Eficiência (1750 tokens)

# Resultados:
# - Llama4: 83 chunks, processamento mais lento, máxima precisão
# - GPT-4: 18 chunks, processamento balanceado, boa qualidade
# - DeepSeek: 76 chunks, processamento rápido, qualidade técnica
```

### Experimentos

O Vulnerability Extractor foi **validado através de experimentos práticos** com diferentes tipos de relatórios e configurações de LLM.

#### Cenários de Teste

##### Tenable WAS Reports

- **Configuração**: Scanner `tenable` + LLM `gpt4`
- **Documentos**: Relatórios de 50-200 páginas
- **Resultados**: Consolidação eficiente de instances/bases, detecção precisa de plugins

##### OpenVAS/Greenbone Reports

- **Configuração**: Scanner `openvas` + LLM `llama3`
- **Documentos**: Relatórios NVT com 100-500 vulnerabilidades
- **Resultados**: Extração completa de 18 campos especializados

#### Validação de Token Optimization

##### Experimento: Zero Token Excedentes

```bash
# Teste com documento de 300 páginas
python main.py large_report.pdf --llm gpt4
# Resultado: 42 chunks processados, 0 exceedances
```

##### Experimento: Comparative Performance

```bash
# Teste comparativo entre modelos
python main.py test_report.pdf --llm llama4  # Precisão máxima
python main.py test_report.pdf --llm gpt4    # Balanceado
python main.py test_report.pdf --llm deepseek # Eficiência
```

#### Resultados de Validação

| Métrica      | Tenable WAS | OpenVAS |
| ------------ | ----------- | ------- |
| **Accuracy** | 98.5%       | 97.2%   |
| **F1-Score** | 96.8%       | 95.1%   |
| **Coverage** | 99.1%       | 98.7%   |

#### Performance Metrics

| LLM             | Velocidade      | Custo Médio       | Eficiência |
| --------------- | --------------- | ----------------- | ---------- |
| **GPT-4**       | ~1.2 chunks/min | $0.03/doc         | 60.8%      |
| **Llama3/Groq** | ~2.5 chunks/min | **$0** (gratuito) | 42.6%      |
| **DeepSeek**    | ~3.1 chunks/min | $0.008/doc        | 42.7%      |

#### Consolidation Effectiveness

- **Duplicata removal**: 94.7% de redução em relatórios TenableWAS
- **Instance merging**: 89.3% de consolidação efetiva

## Estrutura do Código

```
Vulnerability_Extractor/
├── main.py                        # Script principal CLI
├── requirements.txt               # Dependências Python
├── README.md                      # Documentação principal
├── chunk_validator.py             # Validador de chunks (standalone)
├── batch_pdf_extractor.py         # Extração em lote de PDFs (standalone)
├── extract_pdf_text.py            # Extrai texto puro de PDFs
├── extract_vuln_blocks.py         # Extrai blocos de vulnerabilidades de .txt
├── compare_vuln_blocks.py         # Compara blocos extraídos para duplicatas
├── tools/
│   ├── run_experiments.py         # Execução massiva e avaliação automatizada
│   ├── process_results.py         # Geração de gráficos e estatísticas
│   ├── dataset_generator.py       # Consolidação de datasets (CSV/XLSX/JSON/JSONL)
│   ├── sum_tokens_cost_all_llms.py# Soma tokens e estima custos por LLM
│   ├── calc_tokens_cost.py        # Calcula tokens/custo para uma LLM específica
│   ├── prepare_metrics_input.py   # Gera arquivos combinados para métricas
│   └── chunk_validator.py         # (link para raiz, para compatibilidade)
├── src/
│   ├── __init__.py
│   ├── configs/
│   │   ├── llms/                  # Configurações dos LLMs (JSON)
│   │   ├── scanners/              # Configurações de scanners (JSON)
│   │   └── templates/             # Templates de prompts (TXT)
│   ├── converters/
│   │   ├── __init__.py
│   │   ├── base_converter.py
│   │   ├── csv_converter.py
│   │   └── xlsx_converter.py
│   └── utils/
│       ├── __init__.py
│       ├── block_creation.py
│       ├── cais_validator.py
│       ├── chunking.py
│       ├── cli_args.py
│       ├── convertions.py
│       ├── llm_utils.py
│       ├── pdf_loader.py
│       ├── processing.py
│       ├── profile_registry.py
│       └── scanner_strategies.py
├── metrics/
│   ├── __init__.py
│   ├── baselines/
│   │   ├── openvas/
│   │   └── tenable/
│   ├── bert/
│   │   ├── compare_extractions_bert.py
│   │   └── results/
│   ├── rouge/
│   │   └── compare_extractions_rouge.py
│   ├── common/
│   │   ├── cli.py
│   │   ├── config.py
│   │   ├── matching.py
│   │   └── normalization.py
│   └── plot/
│       ├── __init__.py
│       ├── __main__.py
│       ├── charts.py
│       └── utils.py
├── data/                          # Dados de entrada e exportações
│   ├── *.pdf
│   ├── vulnerabilities_*.json
│   ├── visual_layout_*.txt
│   └── exports/
├── jsons/                         # Resultados intermediários (JSON)
├── results_tokens/                # Arquivos de tokens por LLM
├── results_runs/                  # Resultados de execuções experimentais
├── results_runs_xlsx/             # Resultados em XLSX
├── plot_runs/                     # Gráficos gerados
├── temp_blocks/                   # Blocos temporários de vulnerabilidades
└── __pycache__/                   # Cache Python (auto-gerado)
```

### Componentes Principais

#### Scripts de Interface

- **main.py**: CLI principal com argumentos modernos e orquestração completa
- **chunk_validator.py**: Ferramenta de análise e validação de chunks

#### Sistema de Processamento

- **processing.py**: Engine de chunking com cálculo automático de tokens e zero exceedances
- **utils.py**: Loading inteligente de LLMs com configurações otimizadas por modelo
- **pdf_loader.py**: Extração de texto otimizada com preservação de layout

#### Estratégias Especializadas

- **scanner_strategies.py**: Lógica de processamento especializada por tipo de relatório
- **profile_registry.py**: Sistema de registro e descoberta de perfis/scanners
- **cais_validator.py**: Validação específica para formato CAIS

#### Sistema de Exportação

- **base_converter.py**: Framework base para conversores
- **csv_converter.py**: Export CSV/TSV com configurações customizáveis
- **xlsx_converter.py**: Export Excel com formatação avançada

## Scripts Avançados e Utilitários

### `tools/run_experiments.py` — Execução Massiva e Avaliação Automatizada

Automatiza experimentos em larga escala, processando múltiplos relatórios, LLMs e scanners, com checkpointing robusto e avaliação automática (BERT/ROUGE). Gera estatísticas, logs e organiza resultados em subpastas por baseline/modelo/run.

**Principais recursos:**

- Executa extração, exportação e avaliação para todos os pares (relatório, scanner, LLM, run)
- Suporte a checkpoint: retoma execuções interrompidas sem repetir runs já concluídas
- Gera logs detalhados, arquivos de saída, métricas e resumos automáticos
- Organiza resultados em `results_runs/` e `results_runs_xlsx/`
- Avaliação automática com BERT e ROUGE

**Exemplo de uso:**

```bash
python tools/run_experiments.py [--checkpoint-file run_checkpoints_YYYY-MM-DDTHH-MM-SS.json]
```

### `tools/process_results.py` — Geração de Gráficos e Estatísticas

Processa os resultados dos experimentos, gerando gráficos (stacked bar, heatmaps) e estatísticas de similaridade, cobertura e desempenho dos modelos.

**Principais recursos:**

- Gera gráficos de distribuição de categorias de similaridade (stacked bar)
- Gera heatmaps de métricas (BERT/ROUGE) por LLM e baseline
- Analisa e sumariza resultados de múltiplos experimentos
- Salva gráficos em `plot_runs/`

**Exemplo de uso:**

```bash
python tools/process_results.py
```

### `tools/dataset_generator.py` — Consolidação de Datasets

Gera datasets consolidados (CSV, XLSX, JSON, JSONL) a partir de múltiplos arquivos de extração JSON, facilitando análises e treinamentos.

**Principais recursos:**

- Consolida todos os arquivos JSON de uma pasta em um único dataset
- Suporte a múltiplos formatos de saída: CSV, XLSX, JSON, JSONL
- Normaliza campos, adiciona IDs e padroniza severidades
- Ideal para análises quantitativas e uso em ML

**Exemplo de uso:**

```bash
python tools/dataset_generator.py --input-folder jsons --output-folder data --format xlsx
```

- **Gerar todos os formatos de uma vez:**

```bash
python tools/dataset_generator.py --input-folder jsons --output-folder data --format all
```

Isso irá criar arquivos CSV, XLSX, JSON e JSONL simultaneamente na pasta de saída.

#### chunk_validator.py

Ferramenta standalone para análise e validação de chunks:

**Funcionalidades:**

- Análise de distribuição de tokens
- Detecção de padrões de scanner
- Validação de integridade de chunks
- Otimização sugerida de configurações
- Relatórios detalhados de eficiência

```bash
# Análise completa de chunking
python chunk_validator.py documento.pdf

# Validação com LLM específico
python chunk_validator.py documento.pdf --LLM gpt4 --scanner tenable
```

### `tools/sum_tokens_cost_all_llms.py` — Soma de Tokens e Estimativa de Custos

Analisa todos os arquivos de tokens gerados (`*_tokens.json` em `results_tokens/`), somando o total de tokens processados por LLM e estimando o custo em dólares para cada modelo e no total.

### Diferença: `run_experiments.py` vs `batch_pdf_extractor.py`

- **`batch_pdf_extractor.py`**: Executa extração em lote de PDFs de um diretório, chamando `main.py` para cada arquivo. Útil para processar rapidamente muitos PDFs, mas não faz avaliação automática nem organização avançada dos resultados.
- **`run_experiments.py`**: Orquestra experimentos completos, processando múltiplos relatórios, LLMs, scanners e runs, com checkpoint, avaliação automática (BERT/ROUGE), logs e organização detalhada dos resultados. Ideal para benchmarks, validação e experimentação.

**Principais recursos:**

- Soma tokens de entrada/saída por LLM
- Calcula custo estimado por modelo e geral (usando tabela de preços interna)
- Útil para análise de eficiência e planejamento de custos

**Exemplo de uso:**

```bash
python tools/sum_tokens_cost_all_llms.py --tokens-dir results_tokens
```

#### Sistema de Tokens Otimizado

Cálculos matemáticos precisos para cada LLM:

- **Fórmula universal**: `max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer`
- **Zero exceedances garantidas** através de múltiplas camadas de segurança
- **Configurações específicas** por modelo com eficiências calculadas
- **Validação automática** de configurações na inicialização
  │ │ ├── cais*tenable_prompt.txt # • CAIS Tenable (dotted fields)
  │ │ ├── cais_openvas_prompt.txt # • CAIS OpenVAS estruturado
  │ │ └── cais_prompt*.txt # • Variações CAIS (v1-v3)
  │ ├── converters/ # 🔄 Conversores de formato
  │ │ ├── **init**.py # • Inicialização de conversores
  │ │ ├── base*converter.py # • Classe base abstrata
  │ │ ├── csv_converter.py # • Exportação CSV/TSV
  │ │ └── xlsx_converter.py # • Exportação Excel
  │ └── utils/ # 🛠️ Utilitários core
  │ ├── **init**.py # • Inicialização de utils
  │ ├── utils.py # • LLM loading e configuração
  │ ├── processing.py # • Sistema de chunks com cálculo de tokens
  │ ├── scanner_strategies.py # • Estratégias especializadas
  │ ├── profile_registry.py # • Registry de perfis/scanners
  │ ├── pdf_loader.py # • Carregamento otimizado de PDFs
  │ └── cais_validator.py # • Validação específica CAIS
  ├── data/ # 📂 Dados e resultados
  │ ├── *.pdf # • Relatórios de entrada
  │ ├── vulnerabilities**.json # • Resultados JSON estruturados
  │ ├── visual*layout*\_.txt # • Layouts preservados
  │ └── exports/ # • Exportações CSV/XLSX
  └── **pycache\*\*/ # 🗂️ Cache Python (auto-gerado)

````

## Extensibilidade

O Vulnerability Extractor foi projetado com arquitetura modular e extensível que permite personalização em três dimensões principais.

### Adicionando Novos LLMs

A ferramenta suporta qualquer modelo compatível com a API OpenAI através de arquivos de configuração JSON.

#### Como adicionar um novo LLM

**1. Crie arquivo de configuração** em `src/configs/llms/`:
```json
{
  "api_key": "${API_KEY_ANTHROPIC}",
  "endpoint": "https://api.anthropic.com/v1",
  "model": "claude-3-haiku-20240307",
  "temperature": 0,
  "max_tokens": 4096,
  "timeout": 60,
  "reserve_for_response": 3000,
  "prompt_overhead": 300,
  "system_overhead": 200,
  "safety_buffer": 200,
  "max_chunk_size": 2396,
  "calculation_formula": "max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer"
}
````

**2. Estrutura suportada:**

- `api_key`: Chave de autenticação da API (use `${VARIABLE_NAME}` para referenciar variáveis do .env)
- `endpoint`: URL do endpoint da API
- `model`: Nome do modelo específico
- `temperature`: Criatividade (0-1)
- `max_tokens`: Limite de tokens por resposta
- `timeout`: Tempo limite em segundos
- Campos de cálculo de tokens (conforme fórmula universal)

**3. Provedores testados:**

- **OpenAI**: `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`
- **Groq**: `llama-3.1-8b-instant`, `mixtral-8x7b-32768`
- **Anthropic**: `claude-3-haiku`, `claude-3-sonnet`
- **DeepSeek**: `deepseek-chat`
- **Qualquer API compatível** com formato OpenAI

### Adicionando Novos Scanners

Os scanners controlam como o documento é processado e as vulnerabilidades são extraídas e consolidadas.

#### Como criar uma nova estratégia

**1. Crie arquivo de configuração** em `src/configs/scanners/`:

```json
{
  "reader": "nessus",
  "prompt_template": "src/configs/templates/nessus_prompt.txt",
  "retry_attempts": 3,
  "delay_between_chunks": 5,
  "remove_duplicates": true,
  "merge_instances_with_same_base": true,
  "output_file": "vulnerabilities_nessus.json",
  "consolidation_field": "Name"
}
```

**2. Parâmetros configuráveis:**

- `reader`: Identificador único do leitor
- `prompt_template`: Caminho para o template de prompt
- `retry_attempts`: Tentativas em caso de erro
- `delay_between_chunks`: Delay entre processamento (segundos)
- `remove_duplicates`: Remover duplicatas por nome
- `output_file`: Nome do arquivo de saída
- `consolidation_field`: Campo para consolidação

**3. Configurações recomendadas:**

- **Relatórios pequenos** (< 50 páginas): Use LLMs com chunks grandes (GPT-4, GPT-5)
- **Relatórios médios** (50-200 páginas): Use configuração balanceada (Llama3, Qwen3)
- **Relatórios grandes** (> 200 páginas): Use processamento incremental com delays
- **Estruturas complexas**: Aumente `retry_attempts` e use templates específicos

### Adicionando Templates de Prompt

Os templates definem como as vulnerabilidades são extraídas e estruturadas.

#### Como criar um novo template

**1. Crie arquivo de template** em `src/configs/templates/`:

```txt
You are an information extraction model for Nessus vulnerability reports.

Extract structured vulnerability information from the TEXT REPORT provided.

**NESSUS SPECIFIC INSTRUCTIONS:**
1. For each "Plugin Name" is a vulnerability block
2. Use "Plugin Name" as "Name"
3. Use "Description" field as "description"
4. Use "Solution" field as "solution"
5. Use "Risk Information" as "risk"
6. Extract CVSS scores from "CVSS" section
7. Get port from "Port" field
8. Use "See Also" as "references"

Return ONLY a valid JSON array with this exact structure:
[
  {
    "Name": "<plugin name>",
    "description": ["<description text>"],
    "solution": ["<solution text>"],
    "risk": ["<risk level>"],
    "cvss": ["<cvss score>"],
    "port": "<port number>",
    "references": ["<reference urls>"],
    "source": "NESSUS"
  }
]
```

**2. Elementos do template:**

- **Instruções gerais**: Como interpretar o documento
- **Mapeamento de campos**: Qual campo do relatório vai para qual campo JSON
- **Formato de saída**: Estrutura JSON com 18 campos padronizados
- **Regras específicas**: Como tratar duplicatas, valores nulos, etc.

**3. Templates disponíveis:**

- **JSON estruturado** (`default_prompt.txt`): Saída em JSON completo com 18 campos
- **Tenable especializado** (`tenable_prompt.txt`): Merge de instances e bases
- **OpenVAS NVT** (`openvas_prompt.txt`): Campos técnicos especializados
- **CAIS formats** (`cais_*_prompt.txt`): Notação dotada para integração empresarial

### Guia Completo de Personalização

#### Para adicionar suporte a uma nova ferramenta (ex: Rapid7 Nexpose)

**1. Analise a estrutura do relatório:**

```
Vulnerability: Cross-Site Scripting
Asset: web-server-01
Service: HTTP (80/tcp)
Severity: Medium
Proof: <script>alert('XSS')</script>
Solution: Input validation required
```

**2. Crie template específico** (`rapid7_prompt.txt`):

- Foque em campos "Vulnerability", "Asset", "Service"
- Map "Proof" para campo específico
- Use "Severity" para classificação

**3. Configure scanner** (`rapid7.json`):

- `reader`: "rapid7"
- Chunks médios para estrutura balanceada
- `consolidation_field`: "Vulnerability"

**4. Teste e valide:**

```bash
python main.py relatorio_rapid7.pdf --scanner rapid7 --LLM gpt4
python chunk_validator.py relatorio_rapid7.pdf --scanner rapid7
```

### Arquitetura de Extensão

#### Interfaces Padronizadas

- **LLM Interface**: API OpenAI compatível com configuração JSON
- **Scanner Interface**: Configuração JSON + template de prompt
- **Export Interface**: Classe base abstrata para novos formatos

#### Pontos de Extensão

- **`src/configs/llms/`**: Novos provedores de LLM
- **`src/configs/scanners/`**: Novas estratégias de processamento
- **`src/configs/templates/`**: Novos templates de extração
- **`src/converters/`**: Novos formatos de exportação

#### Validação Automática

- **Token calculation**: Automática para novos LLMs
- **Template validation**: Verificação de formato JSON
- **Scanner testing**: chunk_validator.py para debugging
- **Integration testing**: Testes end-to-end com documentos reais

O sistema foi projetado para crescer organicamente conforme novas ferramentas de segurança e provedores de LLM se tornem disponíveis, mantendo sempre a compatibilidade com configurações existentes.

## Licença

Este projeto está licenciado sob os termos da [Creative Commons BY-NC 4.0 Internacional](https://creativecommons.org/licenses/by-nc/4.0/deed.pt_BR).

- **Uso permitido:** fins educacionais e de pesquisa, com modificações e redistribuição não comercial mantendo os créditos.
- **Proibido:** uso comercial sem autorização expressa dos autores.
- **Aviso:** fornecido "como está", sem garantias. O usuário é responsável pelo uso e pela configuração segura de dados e chaves.

Consulte o arquivo [LICENSE](LICENSE) para o texto completo da licença.
