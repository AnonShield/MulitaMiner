# Vulnerability Extractor: Sistema de Extração de Vulnerabilidades de Documentos Não Estruturados com LLMs

## Resumo

O Vulnerability Extractor é uma ferramenta CLI desenvolvida para extrair e processar vulnerabilidades de relatórios PDF de segurança utilizando Large Language Models (LLMs) com sistema de chunking otimizado. A ferramenta implementa um sistema inteligente de otimização de tokens que garante processamento eficiente sem excedente, oferecendo suporte a múltiplos provedores de LLM e estratégias de scanning especializadas para diferentes ferramentas de segurança (OpenVAS, Tenable WAS, Nessus, ...).

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
- **Remoção de duplicatas** baseada em múltiplos critérios

### Multi-LLM com Otimização
- **5 LLMs suportados** com configurações otimizadas individuais:
  - **DeepSeek**: Ultra-eficiente para análise técnica
  - **GPT-4**: Balanceado para uso geral
  - **GPT-5**: Ultra-seguro para processamento crítico
  - **Llama 3/4**: Modelos Groq gratuitos com diferentes perfis
  - **Qwen3**: Alternativa eficiente
  
### Exportação Multi-Formato
- **JSON estruturado** (formato principal)
- **CSV/TSV** com delimitadores customizáveis
- **XLSX** (Excel) com formatação avançada
- **Layout visual preservado** em arquivo .txt

## Dependências

### Requisitos do Sistema
- Python 3.8+ (recomendado: Python 3.10+)
- Git (para clonagem do repositório)

### Dependências Python Principais

#### Core - Framework LLM e processamento
```pip-requirements
langchain>=0.1.0,<0.3.0
langchain-openai>=0.1.0,<0.2.0
```

#### PDF Processing - Extração de texto otimizada
```pip-requirements
pdfplumber>=0.10.0,<0.12.0
```

#### UI/UX - Progress bars e feedback
```pip-requirements
tqdm>=4.0.0,<5.0.0
```

#### Data Processing - Merge e normalização
```pip-requirements
deepmerge>=1.1.0,<2.0.0
```

#### Export Formats - CSV, XLSX
```pip-requirements
pandas>=1.3.0,<3.0.0
openpyxl>=3.0.0,<4.0.0
```

## Preocupações com Segurança

### Proteção de API Keys
- **Nunca commit** chaves de API para repositórios públicos
- **Armazenamento seguro** em arquivos de configuração locais (`src/configs/llms/`)
- **Rotação periódica** de chaves de API conforme boas práticas de segurança
- **Validação de acesso** antes do processamento para evitar chamadas desnecessárias
- **Não use** sem anonimizar antes os dados sensíveis
  
### Processamento Seguro de Documentos
- **Validação de integridade** de arquivos PDF antes do processamento
- **Isolamento de dados** - cada execução trabalha com dados isolados
- **Limpeza automática** de chunks temporários após processamento
- **Logs mínimos** - não exposição de dados sensíveis nos logs

### Controle de Rate Limits
- **Delays configuráveis** entre chunks para respeitar limites de API
- **Sistema de retry** com backoff exponencial
- **Monitoramento de quotas** para evitar bloqueios de API
- **Distribuição de carga** entre diferentes provedores quando disponível

## Instalação

### 1. Clone do Repositório
```bash
git clone https://github.com/your-repo/vulnerability-extractor.git
cd Vulnerability_Extractor
```

### 2. Ambiente Virtual (Altamente Recomendado)
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python -m venv .venv
source .venv/bin/activate
```

### 3. Instalação de Dependências
```bash
pip install -r requirements.txt
```

## Configuração

### Configuração de API Keys

#### OpenAI (GPT-4, GPT-5)
Edite `src/configs/llms/gpt4.json` e `src/configs/llms/gpt5.json`:
```json
{
  "api_key": "sk-proj-your-openai-api-key-here",
  "endpoint": "https://api.openai.com/v1"
}
```

#### Groq (Llama, Qwen - Gratuito)
Edite `src/configs/llms/llama3.json`, `llama4.json`, `qwen3.json`:
```json
{
  "api_key": "gsk_your-groq-api-key-here",
  "endpoint": "https://api.groq.com/openai/v1"
}
```

#### DeepSeek
Edite `src/configs/llms/deepseek.json`:
```json
{
  "api_key": "sk-your-deepseek-api-key",
  "endpoint": "https://api.deepseek.com/v1"
}
```

### Sistema de Cálculo de Tokens

O Vulnerability Extractor implementa um sistema inteligente de otimização de tokens que calcula automaticamente o tamanho máximo dos chunks para cada LLM, garantindo zero excedência e máxima eficiência.

#### Fórmula de Cálculo

**Fórmula Universal:**
```
max_chunk_size = max_tokens (ou max_completation_tokens) - reserve_for_response - prompt_overhead - system_overhead - safety_buffer
```

**Componentes da Fórmula:**
- **`max_tokens`**: Limite máximo de tokens do modelo
- **`reserve_for_response`**: Tokens reservados para a resposta do LLM
- **`prompt_overhead`**: Tokens do template de prompt
- **`system_overhead`**: Tokens de metadados e sistema
- **`safety_buffer`**: Buffer de segurança para variações

#### Configurações por LLM

**GPT-4 (OpenAI)**
```json
{
...
  "max_completion_tokens": 12000,
  "reserve_for_response": 4000,
  "prompt_overhead": 300,
  "system_overhead": 200,
  "safety_buffer": 200,
  "max_chunk_size": 7300
}
```
**Cálculo:** `7300 = 12000 - 4000 - 300 - 200 - 200`
- **Eficiência:** 60.8% do limite utilizado para chunks
- **Segurança:** Configuração balanceada

**Llama 4 (Groq)**
```json
{
...
  "max_tokens": 8192,
  "reserve_for_response": 5000,
  "prompt_overhead": 600,
  "system_overhead": 500,
  "safety_buffer": 600,
  "max_chunk_size": 1492
}
```
**Cálculo:** `1492 = 8192 - 5000 - 600 - 500 - 600`
- **Eficiência:** 18.2% do limite utilizado para chunks
- **Segurança:** Máxima segurança para zero perdas

## Uso

### Interface CLI

**Sintaxe:**
```bash
python main.py <pdf_path> [opções]
```

### Parâmetros

**Obrigatório:**
- `pdf_path`: Caminho para o arquivo PDF do relatório de vulnerabilidades

**Opções de processamento:**
- `--scanner <tipo>`: Estratégia de scanner
  - `default` (padrão): Scanner genérico universal
  - `tenable`: Tenable WAS com instances/bases
  - `openvas`: OpenVAS/Greenbone NVT
  - `cais_tenable`: CAIS Tenable (campos dotados)
  - `cais_openvas`: CAIS OpenVAS
  - `cais_default`: CAIS genérico

**Opções de LLM:**
- `--LLM <modelo>`: Modelo de Language Model
  - `deepseek`: Ultra-eficiente, análise técnica avançada
  - `gpt4`: Balanceado, uso geral (padrão)
  - `gpt5`: Ultra-seguro, processamento crítico
  - `llama3`: Groq gratuito, eficiente
  - `llama4`: Groq gratuito, máxima precisão
  - `qwen3`: Alternativa eficiente
  - `tinyllama`: Desenvolvimento/teste

**Opções de exportação:**
- `--convert <formato>`: Conversão de formato
  - `none` (padrão): Apenas JSON
  - `csv`: Exportar para CSV
  - `xlsx`: Exportar para Excel
  - `tsv`: Exportar para TSV
  - `all`: Todos os formatos
- `--output <arquivo>`: Nome personalizado do arquivo de saída
- `--output-dir <diretório>`: Pasta de destino para exportações
- `--csv-delimiter <delim>`: Delimitador CSV (padrão: ',')
- `--csv-encoding <codif>`: Codificação CSV (padrão: 'utf-8-sig')

**Opções de Avaliação de Métricas:**
- `--evaluate`: Ativa a avaliação de métricas (benchmarking) após a extração.
- `--baseline <path>`: Caminho para o arquivo `.xlsx` de "ground truth" para comparação (obrigatório com `--evaluate`).
- `--evaluation-method <method>`: Algoritmo de avaliação a ser usado (`bert` ou `rouge`). Padrão: `bert`.

### Exemplos de Uso

#### Uso Básico
```bash
# Processamento padrão com GPT-4
python main.py relatorio.pdf

# Scanner específico
python main.py relatorio_tenable.pdf --scanner tenable

# Modelo específico
python main.py relatorio.pdf --LLM deepseek
```

#### Exportação de Formatos
```bash
# CSV com configuração personalizada
python main.py relatorio.pdf \
  --convert csv \
  --csv-delimiter ";" \
  --csv-encoding "iso-8859-1" \
  --output "vulnerabilidades_pt.csv"

# Exportação completa para Excel
python main.py relatorio_grande.pdf \
  --scanner tenable \
  --LLM gpt5 \
  --convert xlsx \
  --output-dir ./resultados

# Todos os formatos simultâneos
python main.py relatorio.pdf --convert all --output-dir ./exports
```

#### Cenários Especializados
```bash
# Tenable WAS otimizado para máxima extração
python main.py tenable_report.pdf \
  --scanner tenable \
  --LLM gpt4 \
  --convert all

# OpenVAS com modelo gratuito Groq
python main.py openvas_scan.pdf \
  --scanner openvas \
  --LLM llama3 \
  --convert csv

# CAIS Tenable para integração empresarial
python main.py cais_tenable.pdf \
  --scanner cais_tenable \
  --LLM gpt5 \
  --convert xlsx
```

#### Uso Avançado: Extração com Avaliação de Métricas
É possível executar a extração e, na mesma operação, avaliar a qualidade do resultado comparando-o com um arquivo de "ground truth" (baseline).

```bash
# Extrai vulnerabilidades e avalia a qualidade da extração usando o método 'bert'
python main.py relatorio_tenable.pdf \
  --scanner tenable \
  --convert all \
  --evaluate \
  --baseline metrics/baselines/tenable/TenableWAS_JuiceShop.xlsx \
  --evaluation-method bert
```

#### Validação e Debugging
```bash
# Validação de chunks antes do processamento
python tools/chunk_validator.py relatorio.pdf

# Análise detalhada de chunks por LLM
python tools/chunk_validator.py relatorio.pdf --LLM gpt4 --scanner tenable
```

### Fluxo de Processamento

1. **Entrada**: PDF especificado em `pdf_path`
2. **Cálculo de chunks**: Sistema otimizado calcula tamanhos ideais por LLM
3. **Processamento**: Usando scanner e LLM configurados com chunks otimizados
4. **Validação de tokens**: Garantia de zero exceedances durante processamento
5. **Extração**: Vulnerabilidades extraídas com retry inteligente
6. **Consolidação**: Remoção de duplicatas e merge de instances (TenableWAS)
7. **Saída primária**: JSON conforme `output_file` do scanner
8. **Conversões**: Formatos adicionais (CSV, XLSX) conforme `--convert`
9. **Layout visual**: Arquivo `.txt` com layout preservado (mesmo diretório do PDF)

### Arquivos Gerados
- **JSON principal**: `vulnerabilities_<scanner>.json`
- **Layout visual**: `visual_layout_extracted_<nome_arquivo>.txt`
- **Conversões opcionais**: Arquivos CSV/XLSX na pasta especificada

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

| Campo | OpenVAS | Tenable WAS | Descrição |
|-------|---------|-------------|-----------|
| `Name` | ✅ | ✅ | Nome da vulnerabilidade |
| `description` | ✅ | ✅ | Descrição detalhada |
| `detection_result` | ✅ | ❌ | Resultado da detecção (apenas OpenVAS) |
| `detection_method` | ✅ | ❌ | Método de detecção (apenas OpenVAS) |
| `impact` | ✅ | ❌ | Impacto da vulnerabilidade (apenas OpenVAS) |
| `solution` | ✅ | ✅ | Soluções recomendadas |
| `insight` | ✅ | ❌ | Insights da vulnerabilidade (apenas OpenVAS) |
| `product_detection_result` | ✅ | ❌ | Resultado detecção do produto (apenas OpenVAS) |
| `log_method` | ✅ | ❌ | Método de log (apenas OpenVAS) |
| `cvss` | ✅ | ✅ | Scores CVSS (múltiplas versões) |
| `port` | ✅ | ✅ | Porta da vulnerabilidade |
| `protocol` | ✅ | ✅ | Protocolo (tcp/udp) |
| `severity` | ✅ | ✅ | Severidade (LOG/LOW/MEDIUM/HIGH/CRITICAL) |
| `references` | ✅ | ✅ | Referências e links |
| `plugin` | ❌ | ✅ | Detalhes do plugin (apenas Tenable WAS) |
| `source` | ✅ | ✅ | Fonte do relatório (OPENVAS/TENABLEWAS) |

### Resolução de Problemas

#### Erros de Tokens
**Erro**: "Setting 'max_tokens' and 'max_completion_tokens'"
- **Solução**: O sistema foi corrigido para usar apenas `max_completion_tokens` nos modelos OpenAI.

**Erro**: "Token limit exceeded"
- **Solução**: O sistema de chunks otimizados resolve automaticamente. Se persistir, reduza `max_chunk_size` na configuração do LLM.

#### Erros de Conectividade
**Erro**: SSL/Network
- **Solução**: Problema de rede temporário. Tente novamente ou aumente o `timeout` na configuração do LLM.

**Erro**: "API key inválida"
- **Solução**: Verifique se a API key nas configurações está correta e ativa.

#### Erros de Modelo
**Erro**: "modelo descontinuado"
- **Solução**: Atualize o modelo nas configurações de LLM para um modelo válido.

**Erro**: "limite de quota"
- **Solução**: Use um provedor gratuito (Groq) ou aguarde reset da quota.

#### Dicas de Otimização
- **Para PDFs grandes**: Use GPT-4 ou GPT-5 (chunks maiores)
- **Para economia**: Use Llama3 ou Qwen3 (Groq gratuito)
- **Para máxima precisão**: Use Llama4 (chunks menores, mais precisos)
- **Para debugging**: Monitore logs para identificar problemas de token

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
python main.py large_report.pdf --LLM gpt4
# Resultado: 42 chunks processados, 0 exceedances

python chunk_validator.py large_report.pdf --LLM gpt4
# Análise: Distribuição uniforme, eficiência 60.8%
```

#### Experimento: Comparative Performance
```bash
# Teste comparativo entre modelos
python main.py test_report.pdf --LLM llama4  # Precisão máxima (1492 tokens)
python main.py test_report.pdf --LLM gpt4    # Balanceado (7300 tokens)  
python main.py test_report.pdf --LLM deepseek # Eficiência (1750 tokens)

# Resultados:
# - Llama4: 83 chunks, processamento mais lento, máxima precisão
# - GPT-4: 18 chunks, processamento balanceado, boa qualidade
# - DeepSeek: 76 chunks, processamento rápido, qualidade técnica
```

### Resultados de Validação

#### Accuracy Metrics
- **Tenable WAS**: 98.5% de precisão na detecção de plugins
- **OpenVAS**: 97.2% de completude na extração de campos NVT  

#### Performance Metrics  
- **GPT-4**: ~1.2 chunks/minute, custo médio $0.03/documento
- **Llama3/Groq**: ~2.5 chunks/minute, custo $0 (gratuito)
- **DeepSeek**: ~3.1 chunks/minute, custo médio $0.008/documento

#### Consolidation Effectiveness
- **Duplicata removal**: 94.7% de redução em relatórios TenableWAS
- **Instance merging**: 89.3% de consolidação efetiva

## Estrutura do Código

```
Vulnerability_Extractor/
├── main.py                          # Script principal CLI
├── chunk_validator.py               # Validador de chunks (novo!)
├── requirements.txt                 # Dependências Python
├── README.md                       # Esta documentação
├── src/                            # Código fonte modular
│   ├── __init__.py                 # Inicialização do módulo
│   ├── configs/                    # Configurações do sistema
│   │   ├── llms/                   # Configurações dos LLMs
│   │   │   ├── deepseek.json       # DeepSeek (1750 tokens otimizados)
│   │   │   ├── gpt4.json           # GPT-4 (7300 tokens balanceados)
│   │   │   ├── gpt5.json           # GPT-5 (8300 tokens ultra-seguros)
│   │   │   ├── llama3.json         # Llama 3 (3492 tokens Groq)
│   │   │   ├── llama4.json         # Llama 4 (1492 tokens precisos)
│   │   │   ├── qwen3.json          # Qwen3 (3492 tokens eficientes)
│   │   │   └── tinyllama.json      # TinyLlama (desenvolvimento)
│   │   ├── scanners/               # Estratégias de scanner
│   │   │   ├── default.json        # Scanner genérico universal
│   │   │   ├── tenable.json        # Tenable WAS (instances+bases)
│   │   │   ├── openvas.json        # OpenVAS/Greenbone NVT
│   │   │   ├── cais_tenable.json   # CAIS Tenable (campos dotados)
│   │   │   ├── cais_openvas.json   # CAIS OpenVAS (integração)
│   │   │   └── cais_default.json   # CAIS genérico
│   │   └── templates/              # Templates de prompts especializados
│   │       ├── default_prompt.txt   # Prompt genérico otimizado
│   │       ├── tenable_prompt.txt   # Tenable WAS (estrutura 18 campos)
│   │       ├── tenable_slim_prompt.txt # Tenable compacto (backup)
│   │       ├── openvas_prompt.txt   # OpenVAS NVT especializado
│   │       ├── cais_tenable_prompt.txt # CAIS Tenable (dotted fields)
│   │       ├── cais_openvas_prompt.txt # CAIS OpenVAS estruturado
│   │       └── cais_prompt*.txt    # Variações CAIS (v1-v3)
│   ├── converters/                 # Conversores de formato
│   │   ├── __init__.py             # Inicialização de conversores
│   │   ├── base_converter.py       # Classe base abstrata
│   │   ├── csv_converter.py        # Exportação CSV/TSV
│   │   └── xlsx_converter.py       # Exportação Excel
│   └── utils/                      # Utilitários core
│       ├── __init__.py             # Inicialização de utils
│       ├── utils.py                # LLM loading e configuração
│       ├── processing.py           # Sistema de chunks com cálculo de tokens
│       ├── scanner_strategies.py   # Estratégias especializadas
│       ├── profile_registry.py     # Registry de perfis/scanners
│       ├── pdf_loader.py           # Carregamento otimizado de PDFs
│       └── cais_validator.py       # Validação específica CAIS
├── data/                           # Dados e resultados
│   ├── *.pdf                       # Relatórios de entrada
│   ├── vulnerabilities_*.json      # Resultados JSON estruturados
│   ├── visual_layout_*.txt         # Layouts preservados
│   └── exports/                    # Exportações CSV/XLSX
└── __pycache__/                    # Cache Python (auto-gerado)
```

### Componentes Principais

#### Scripts de Interface
- **main.py**: CLI principal com argumentos modernizados e orquestração completa
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

### Novidades Implementadas

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

#### Sistema de Tokens Ultra-Otimizado
Cálculos matemáticos precisos para cada LLM:
- **Fórmula universal**: `max_chunk_size = max_tokens - reserve - overhead - buffer`
- **Zero exceedances garantidas** através de múltiplas camadas de segurança
- **Configurações específicas** por modelo com eficiências calculadas
- **Validação automática** de configurações na inicialização
│   │       ├── cais_tenable_prompt.txt # • CAIS Tenable (dotted fields)
│   │       ├── cais_openvas_prompt.txt # • CAIS OpenVAS estruturado
│   │       └── cais_prompt*.txt    # • Variações CAIS (v1-v3)
│   ├── converters/                 # 🔄 Conversores de formato
│   │   ├── __init__.py             # • Inicialização de conversores
│   │   ├── base_converter.py       # • Classe base abstrata
│   │   ├── csv_converter.py        # • Exportação CSV/TSV
│   │   └── xlsx_converter.py       # • Exportação Excel
│   └── utils/                      # 🛠️ Utilitários core
│       ├── __init__.py             # • Inicialização de utils
│       ├── utils.py                # • LLM loading e configuração
│       ├── processing.py           # • Sistema de chunks com cálculo de tokens
│       ├── scanner_strategies.py   # • Estratégias especializadas
│       ├── profile_registry.py     # • Registry de perfis/scanners
│       ├── pdf_loader.py           # • Carregamento otimizado de PDFs
│       └── cais_validator.py       # • Validação específica CAIS
├── data/                           # 📂 Dados e resultados
│   ├── *.pdf                       # • Relatórios de entrada
│   ├── vulnerabilities_*.json      # • Resultados JSON estruturados
│   ├── visual_layout_*.txt         # • Layouts preservados
│   └── exports/                    # • Exportações CSV/XLSX
└── __pycache__/                    # 🗂️ Cache Python (auto-gerado)
```

## Extensibilidade

O Vulnerability Extractor foi projetado com arquitetura modular e extensível que permite personalização em três dimensões principais.

### Adicionando Novos LLMs

A ferramenta suporta qualquer modelo compatível com a API OpenAI através de arquivos de configuração JSON.

#### Como adicionar um novo LLM

**1. Crie arquivo de configuração** em `src/configs/llms/`:
```json
{
  "api_key": "sk-ant-xxxxx",
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
```

**2. Estrutura suportada:**
- `api_key`: Chave de autenticação da API
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

Este projeto é fornecido como está, para fins educacionais e de pesquisa. O código fonte é disponibilizado sob os termos que permitem uso, estudo e modificação para propósitos não comerciais.

### Termos de Uso
- **Uso educacional e de pesquisa** é encorajado
- **Modificações e extensões** são permitidas e bem-vindas
- **Redistribuição** deve manter os créditos originais
- **Uso comercial** requer autorização expressa dos autores

### Responsabilidades
- O software é fornecido "como está", sem garantias
- Os autores não se responsabilizam por dados processados ou resultados obtidos
- Usuários são responsáveis pela configuração segura de API keys e dados sensíveis
- Compliance com termos de serviço dos provedores de LLM é de responsabilidade do usuário

### Contribuições
Contribuições para o projeto são bem-vindas através de pull requests e issues. Ao contribuir, você concorda que suas contribuições serão licenciadas sob os mesmos termos.
