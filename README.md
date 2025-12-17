# 🔍 Vulnerability Extractor

Uma ferramenta CLI para extrair vulnerabilidades de relatórios PDF de segurança usando LLMs (Large Language Models).

## 📋 Descrição

Esta ferramenta processa relatórios PDF de segurança e extrai vulnerabilidades estruturadas em formato JSON usando modelos de IA. Suporta diferentes provedores de LLM como OpenAI, Groq, e outros compatíveis com a API OpenAI.

## ✨ Funcionalidades

- ✅ Extração automática de vulnerabilidades de PDFs
- ✅ **Consolidação avançada de vulnerabilidades duplicadas**
  - **TenableWAS**: Merge inteligente de instances e bases
  - **OpenVAS**: Agrupamento por similaridade
- ✅ **Sistema de chunks otimizado** com validação automática
- ✅ Remoção de duplicatas baseada no nome da vulnerabilidade
- ✅ Suporte a múltiplos provedores de LLM (OpenAI, Groq, etc.)
- ✅ **Configuração modernizada** (profiles → scanners)
- ✅ **Interface CLI aprimorada** (--profile → --scanner)
- ✅ Processamento em chunks para documentos grandes
- ✅ **Sistema robusto de recuperação de erros**

## 🚀 Instalação

### 1. Clone ou baixe os arquivos
```bash
git clone <repositório>
cd pdf-vulnerability-extractor
```

### 2. Crie um ambiente virtual (recomendado)
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# ou
source venv/bin/activate  # Linux/Mac
```

### 3. Instale as dependências
```bash
pip install -r requirements.txt
```

### Dependências principais:
- `langchain` - Framework principal para LLM
- `langchain-openai` - Interface para APIs OpenAI/Groq
- `langchain-community` - Loaders e utilitários
- `unstructured[pdf]` - Processamento de PDFs

## ⚙️ Configuração

### 1. Arquitetura extensível

A ferramenta foi projetada com uma arquitetura modular e extensível que permite personalização em três dimensões principais:

#### 🧠 **Modelos LLM configuráveis**

A ferramenta suporta qualquer modelo compatível com a API OpenAI através de arquivos de configuração JSON.

**Como adicionar um novo LLM:**

1. **Crie um arquivo de configuração** em `src/configs/llms/`:
```json
// src/configs/llms/claude.json
{
  "api_key": "sk-ant-xxxxx",
  "endpoint": "https://api.anthropic.com/v1",
  "model": "claude-3-haiku-20240307",
  "temperature": 0,
  "max_tokens": 4096,
  "timeout": 60
}
```

2. **Estrutura suportada:**
   - `api_key`: Chave de autenticação da API
   - `endpoint`: URL do endpoint da API
   - `model`: Nome do modelo específico
   - `temperature`: Criatividade (0-1)
   - `max_tokens`: Limite de tokens por resposta
   - `timeout`: Tempo limite em segundos

3. **Exemplos de provedores suportados:**
   - **OpenAI**: `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`
   - **Groq**: `llama-3.1-8b-instant`, `mixtral-8x7b-32768`
   - **Anthropic**: `claude-3-haiku`, `claude-3-sonnet`
   - **Qualquer API compatível** com formato OpenAI

#### ⚙️ **Estratégias de scanner configuráveis**

Os profiles controlam como o documento é processado e as vulnerabilidades são extraídas e consolidadas.

**Como criar uma nova estratégia:**

1. **Crie um arquivo de configuração** em `src/configs/scanners/`:
```json
// src/configs/scanners/nessus.json
{
  "reader": "nessus", 
  "prompt_template": "src/configs/templates/nessus_prompt.txt",
  "retry_attempts": 3,
  "delay_between_chunks": 5,
  "remove_duplicates": true,
  "merge_instances_with_same_base": true,
  "output_file": "vulnerabilities_nessus.json",
  "chunk_size": 12000,
  "chunk_overlap": 300,
  "separator": "\n\n---\n\n"
}
```

2. **Parâmetros configuráveis:**
   - `reader`: Identificador único do leitor
   - `prompt_template`: Caminho para o template de prompt
   - `retry_attempts`: Tentativas em caso de erro
   - `delay_between_chunks`: Delay entre processamento (segundos)
   - `remove_duplicates`: Remover duplicatas por nome
   - `output_file`: Nome do arquivo de saída
   - `chunk_size`: Tamanho dos chunks de texto
   - `chunk_overlap`: Sobreposição entre chunks
   - `separator`: Separador para divisão de texto

3. **Configurações recomendadas por tipo:**
   - **Relatórios pequenos** (< 50 páginas): `chunk_size: 4000-8000`
   - **Relatórios médios** (50-200 páginas): `chunk_size: 8000-16000`
   - **Relatórios grandes** (> 200 páginas): `chunk_size: 16000-32000`
   - **Estruturas complexas**: `chunk_overlap: 200-500`
   - **Estruturas simples**: `chunk_overlap: 0-200`

#### 📋 **Templates de prompt customizáveis**

Os templates definem como as vulnerabilidades são extraídas e estruturadas.

**Como criar um novo template:**

1. **Crie um arquivo de template** em `src/configs/templates/`:
```txt
// src/configs/templates/nessus_prompt.txt
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

Return JSON format:
[
  {
    "Name": "<plugin name>",
    "description": "<description text>",
    "solution": "<solution text>",
    "risk": "<risk level>",
    "cvss": "<cvss score>",
    "port": "<port number>",
    "references": ["<reference urls>"]
  }
]
```

2. **Elementos do template:**
   - **Instruções gerais**: Como interpretar o documento
   - **Mapeamento de campos**: Qual campo do relatório vai para qual campo JSON
   - **Formato de saída**: Estrutura JSON ou texto esperada
   - **Regras específicas**: Como tratar duplicatas, valores nulos, etc.

3. **Tipos de template disponíveis:**
   - **JSON estruturado** (`default_prompt.txt`): Saída em JSON completo
   - **Texto estruturado** (`default_prompt_struct.txt`): Saída em texto formatado
   - **Simplificado** (`openvas_prompt.txt`, `tenable_prompt.txt`): Campos básicos

#### 🔧 **Guia completo de personalização**

**Para adicionar suporte a uma nova ferramenta (ex: Nessus):**

1. **Analise a estrutura do relatório:**
```bash
# Exemplo: estrutura típica do Nessus
Plugin Name: SQL Injection
Description: The application is vulnerable...
Solution: Implement proper validation...
CVSS: 7.5
Port: 80/tcp
See Also: https://...
```

2. **Crie o template de prompt:**
```bash
# src/configs/templates/nessus_prompt.txt
# (conforme exemplo acima)
```

3. **Configure o perfil:**
```bash
# src/configs/profile/nessus.json
# (conforme exemplo acima)
```

4. **Configure o LLM** (se necessário):
```bash
# src/configs/llms/specialized_model.json
# (para modelos específicos se necessário)
```

5. **Teste e ajuste:**
```bash
python main.py relatorio_nessus.pdf --profile nessus --LLM specialized_model
```

#### 🚀 **Exemplos práticos de extensão**

**Exemplo 1: Adicionando Rapid7 Nexpose**
- Template focado em "Vulnerability Details" e "Remediation"
- Perfil com chunks grandes devido à estrutura detalhada
- Campos específicos: `asset`, `service`, `proof`

**Exemplo 2: Adicionando Qualys VMDR** 
- Template para estrutura XML/HTML
- Perfil com overlap alto devido à formatação complexa
- Campos específicos: `qid`, `category`, `pci_flag`

**Exemplo 3: Adicionando relatórios personalizados**
- Template genérico configurável
- Perfil adaptável via parâmetros
- Saída em múltiplos formatos (JSON, CSV, XML)

## 🧮 Sistema de Cálculo de Tokens

O Vulnerability Extractor implementa um sistema inteligente de otimização de tokens que calcula automaticamente o tamanho máximo dos chunks para cada LLM, garantindo zero exceedances e máxima eficiência.

### 📏 Fórmula de Cálculo

**Fórmula Universal:**
```
max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer
```

**Componentes da Fórmula:**
- **`max_tokens`**: Limite máximo de tokens do modelo
- **`reserve_for_response`**: Tokens reservados para a resposta do LLM
- **`prompt_overhead`**: Tokens do template de prompt
- **`system_overhead`**: Tokens de metadados e sistema
- **`safety_buffer`**: Buffer de segurança para variações

### 🔧 Configurações por LLM

#### **GPT-4 (OpenAI)**
```json
{
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

#### **GPT-5 (OpenAI)**
```json
{
  "max_completion_tokens": 16000,
  "reserve_for_response": 6000,
  "prompt_overhead": 600,
  "system_overhead": 500,
  "safety_buffer": 600,
  "max_chunk_size": 8300
}
```
**Cálculo:** `8300 = 16000 - 6000 - 600 - 500 - 600`
- **Eficiência:** 51.9% do limite utilizado para chunks
- **Segurança:** Ultra-seguro para máxima estabilidade

#### **Llama 3 (Groq)**
```json
{
  "max_tokens": 8192,
  "reserve_for_response": 4000,
  "prompt_overhead": 300,
  "system_overhead": 200,
  "safety_buffer": 200,
  "max_chunk_size": 3492
}
```
**Cálculo:** `3492 = 8192 - 4000 - 300 - 200 - 200`
- **Eficiência:** 42.6% do limite utilizado para chunks
- **Segurança:** Configuração conservadora

#### **Llama 4 (Groq)**
```json
{
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

#### **Qwen3 (Groq)**
```json
{
  "max_tokens": 8192,
  "reserve_for_response": 4000,
  "prompt_overhead": 300,
  "system_overhead": 200,
  "safety_buffer": 200,
  "max_chunk_size": 3492
}
```
**Cálculo:** `3492 = 8192 - 4000 - 300 - 200 - 200`
- **Eficiência:** 42.6% do limite utilizada para chunks
- **Segurança:** Configuração balanceada

### 🎯 Estratégias de Otimização

#### **Nível Conservador** (Llama4)
- Buffer de segurança: **600 tokens**
- Eficiência: ~18% dos tokens para chunks
- **Quando usar:** Modelos instáveis, documentos críticos

#### **Nível Balanceado** (GPT-4, Llama3, Qwen3)  
- Buffer de segurança: **200 tokens**
- Eficiência: ~43-61% dos tokens para chunks
- **Quando usar:** Uso geral, boa relação eficiência/segurança

#### **Nível Ultra-Seguro** (GPT-5)
- Buffer de segurança: **600 tokens**
- Reserva para resposta: **6000 tokens**
- Eficiência: ~52% dos tokens para chunks
- **Quando usar:** Processamento crítico, máxima confiabilidade

### 📊 Benefícios do Sistema

✅ **Zero Exceedances Garantidas**: Nunca ultrapassa limites de tokens
✅ **Otimização Automática**: Calcula tamanhos ideais para cada modelo
✅ **Flexibilidade**: Configurações ajustáveis por LLM
✅ **Confiabilidade**: Múltiplas camadas de segurança
✅ **Eficiência**: Maximiza uso de tokens sem desperdício
✅ **Escalabilidade**: Suporta qualquer modelo compatível

### 🔬 Como Personalizar

Para ajustar os cálculos para suas necessidades:

1. **Edite o arquivo JSON** do LLM em `src/configs/llms/`
2. **Modifique os parâmetros:**
   - Aumente `safety_buffer` para máxima segurança
   - Reduza `reserve_for_response` para chunks maiores
   - Ajuste `prompt_overhead` conforme seus templates
3. **Teste a configuração** com documentos reais
4. **Monitore os logs** para validar eficiência

**Dica:** Use configurações conservadoras inicialmente e otimize gradualmente conforme a estabilidade observada.

## 📖 Uso

### Sintaxe completa:
```bash
python main.py <pdf_path> [opções]
```

### Argumentos obrigatórios:
- **`pdf_path`**: Caminho para o arquivo PDF do relatório de vulnerabilidades

### Argumentos opcionais:
- **`--scanner <tipo>`**: Estratégia de scanner (default, tenable, openvas, cais_tenable, cais_openvas)
- **`--LLM <modelo>`**: Modelo LLM (deepseek, gpt4, gpt5, llama3, llama4, qwen3, tinyllama)
- **`--convert <formato>`**: Formato de conversão (csv, xlsx, all)
- **`--output <arquivo>`**: Nome do arquivo de saída personalizado
- **`--output-dir <diretório>`**: Diretório de saída para conversões
- **`--csv-delimiter <delim>`**: Delimitador CSV (padrão: ',')
- **`--csv-encoding <codif>`**: Codificação CSV (padrão: 'utf-8')
- **`--help`**: Exibe ajuda completa
- `pdf_path` - Caminho para o arquivo PDF a ser processado

### Opções de configuração:

| Opção | Descrição | Padrão | Exemplo |
|-------|-----------|--------|---------|
| `--scanner` | Estratégia de scanner a usar | `default` | `--scanner tenable` |
| `--LLM` | Modelo LLM a usar | `gpt4` | `--LLM llama3` |

### Opções de conversão de saída:

| Opção | Descrição | Valores | Exemplo |
|-------|-----------|---------|---------|
| `--convert` | Formato de conversão da saída | `csv`, `xlsx`, `tsv`, `all`, `none` | `--convert csv` |
| `--output` | Caminho específico do arquivo convertido | Caminho do arquivo | `--output relatorio.csv` |
| `--output-dir` | Diretório para arquivos convertidos | Caminho do diretório | `--output-dir ./resultados` |
| `--csv-delimiter` | Delimitador para arquivos CSV | `,` (vírgula) | `--csv-delimiter ";"` |
| `--csv-encoding` | Codificação para arquivos CSV | `utf-8-sig` | `--csv-encoding utf-8` |

### Exemplos de uso:

#### Uso básico:
```bash
python main.py relatorio.pdf
```

#### Com estratégia específica:
```bash
python main.py relatorio.pdf --scanner tenable
```

#### Com modelo LLM específico:
```bash
python main.py relatorio.pdf --LLM deepseek
```

#### Com conversão para CSV:
```bash
python main.py relatorio.pdf --convert csv
```

#### Com conversão para todos os formatos:
```bash
python main.py relatorio.pdf --convert all --output-dir ./resultados
```

#### CSV com configuração personalizada:
```bash
python main.py relatorio.pdf \
  --convert csv \
  --csv-delimiter ";" \
  --csv-encoding "iso-8859-1" \
  --output "relatorio_pt.csv"
```

#### Processamento com diferentes scanners:
```bash
# TenableWAS com otimização de tokens
python main.py relatorio_tenable.pdf --scanner tenable --LLM gpt4

# OpenVAS com modelo Groq gratuito
python main.py relatorio_openvas.pdf --scanner openvas --LLM llama3

# Scanner genérico com DeepSeek
python main.py relatorio_custom.pdf --scanner default --LLM deepseek

# Processamento com chunking otimizado
python main.py relatorio_grande.pdf --scanner tenable --LLM gpt5 --convert all
```

### 📁 Fluxo de arquivos:

1. **📥 Entrada**: PDF especificado em `pdf_path`
2. **🧮 Cálculo de chunks**: Sistema otimizado calcula tamanhos ideais por LLM
3. **⚙️ Processamento**: Usando scanner e LLM configurados com chunks otimizados
4. **🛡️ Validação de tokens**: Garantia de zero exceedances durante processamento
5. **📋 Extração**: Vulnerabilidades extraídas com retry inteligente
6. **🔄 Consolidação**: Remoção de duplicatas e merge de instances (TenableWAS)
7. **💾 Saída primária**: JSON conforme `output_file` do scanner
8. **🔄 Conversões**: Formatos adicionais (CSV, XLSX) conforme `--convert`
9. **👁️ Layout visual**: Arquivo `.txt` com layout preservado (mesmo diretório do PDF)

### 🎯 Arquivos gerados:
- **JSON principal**: `vulnerabilities_<scanner>.json`
- **Layout visual**: `visual_layout_extracted_<nome_arquivo>.txt`
- **Conversões opcionais**: Arquivos CSV/XLSX na pasta especificada

### Ajuda:
```bash
python main.py --help
```

## 📄 Formato de saída

A ferramenta gera um arquivo JSON com as vulnerabilidades encontradas. O formato completo inclui campos específicos para diferentes tipos de relatórios:

### Estrutura JSON de saída:

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

### Mapeamento de campos por ferramenta:

| Campo | OpenVAS | Tenable WAS | Ambos | Descrição |
|-------|---------|-------------|-------|-----------|
| `Name` | ✅ | ✅ | ✅ | Nome da vulnerabilidade |
| `description` | ✅ | ✅ | ✅ | Descrição detalhada |
| `detection_result` | ✅ | ❌ (null) | ❌ | Resultado da detecção (apenas OpenVAS) |
| `detection_method` | ✅ | ❌ (null) | ❌ | Método de detecção (apenas OpenVAS) |
| `impact` | ✅ | ❌ (null) | ❌ | Impacto da vulnerabilidade (apenas OpenVAS) |
| `solution` | ✅ | ✅ | ✅ | Soluções recomendadas |
| `insight` | ✅ | ❌ (null) | ❌ | Insights da vulnerabilidade (apenas OpenVAS) |
| `product_detection_result` | ✅ | ❌ (null) | ❌ | Resultado detecção do produto (apenas OpenVAS) |
| `log_method` | ✅ | ❌ (null) | ❌ | Método de log (apenas OpenVAS) |
| `cvss` | ✅ | ✅ | ✅ | Scores CVSS (múltiplas versões) |
| `port` | ✅ | ✅ | ✅ | Porta da vulnerabilidade |
| `protocol` | ✅ | ✅ | ✅ | Protocolo (tcp/udp) |
| `severity` | ✅ | ✅ | ✅ | Severidade (LOG/LOW/MEDIUM/HIGH/CRITICAL) |
| `references` | ✅ | ✅ | ✅ | Referências e links |
| `plugin` | ❌ (null) | ✅ | ❌ | Detalhes do plugin (apenas Tenable WAS) |
| `source` | ✅ | ✅ | ✅ | Fonte do relatório (OPENVAS/TENABLEWAS) |

### Campos específicos por ferramenta:

#### OpenVAS exclusivos:
- `detection_result` - Resultado da detecção da vulnerabilidade
- `detection_method` - Método usado para detectar a vulnerabilidade  
- `impact` - Descrição do impacto da vulnerabilidade
- `insight` - Insights sobre a vulnerabilidade
- `product_detection_result` - Resultado da detecção do produto
- `log_method` - Método de logging utilizado

#### Tenable WAS exclusivos:
- `plugin` - Informações detalhadas do plugin

#### Campos compartilhados:
- `Name`, `description`, `solution`, `cvss`, `port`, `protocol`, `severity`, `references`, `source`

## 🔧 Resolução de problemas

### ⚠️ Erros de Tokens

#### Erro: "Setting 'max_tokens' and 'max_completion_tokens'"
```
Error code: 400 - Setting 'max_tokens' and 'max_completion_tokens' at the same time
```
**Solução:** O sistema foi corrigido para usar apenas `max_completion_tokens` nos modelos OpenAI.

#### Erro: "Token limit exceeded"
```
MAX TOKENS EXCEEDED: chunk tem X tokens, limite Y
```
**Solução:** O sistema de chunks otimizados resolve automaticamente. Se persistir, reduza `max_chunk_size` na configuração do LLM.

### 🌐 Erros de Conectividade

#### Erro: SSL/Network
```
SSL: CERTIFICATE_VERIFY_FAILED
```
**Solução:** Problema de rede temporário. Tente novamente ou aumente o `timeout` na configuração do LLM.

#### Erro: "API key inválida"
```
Error: 401 - Unauthorized
```
**Solução:** Verifique se a API key nas configurações está correta e ativa.

### 🤖 Erros de Modelo

#### Erro: "modelo descontinuado"
```
ERRO: O modelo 'llama3-8b-8192' foi descontinuado!
```
**Solução:** Atualize o modelo nas configurações de LLM para um modelo válido.

#### Erro: "limite de quota"
```
Limite de quota atingido no chunk X
```
**Solução:** Use um provedor gratuito (Groq) ou aguarde reset da quota.

### 📄 Erros de Arquivo

#### Erro: "arquivo não encontrado"
```
Erro: Arquivo PDF não encontrado: arquivo.pdf
```
**Solução:** Verifique se o caminho do PDF está correto e o arquivo existe.

#### Erro: "PDF corrupto"
```
Erro ao processar PDF: arquivo corrompido
```
**Solução:** Verifique a integridade do PDF ou converta para uma versão mais recente.

### 🎯 Dicas de Otimização

- **Para PDFs grandes**: Use GPT-4 ou GPT-5 (chunks maiores)
- **Para economia**: Use Llama3 ou Qwen3 (Groq gratuito)
- **Para máxima precisão**: Use Llama4 (chunks menores, mais precisos)
- **Para debugging**: Monitore logs para identificar problemas de token

## 📁 Estrutura do projeto

```
Vulnerability_Extractor/
├── main.py                          # 🎯 Script principal CLI
├── requirements.txt                 # 📦 Dependências Python
├── README.md                       # 📖 Esta documentação
├── src/                            # 🧩 Código fonte modular
│   ├── __init__.py                 # 📋 Inicialização do módulo
│   ├── configs/                    # ⚙️ Configurações do sistema
│   │   ├── llms/                   # 🤖 Configurações dos LLMs
│   │   │   ├── deepseek.json       # • DeepSeek (tokens otimizados)
│   │   │   ├── gpt4.json           # • GPT-4 (OpenAI)
│   │   │   ├── gpt5.json           # • GPT-5 (OpenAI ultra-seguro)
│   │   │   ├── llama3.json         # • Llama 3 (Groq balanceado)
│   │   │   ├── llama4.json         # • Llama 4 (Groq conservador)
│   │   │   ├── qwen3.json          # • Qwen3 (Groq)
│   │   │   └── tinyllama.json      # • TinyLlama (teste)
│   │   ├── scanners/               # 📊 Estratégias de scanner
│   │   │   ├── default.json        # • Scanner genérico
│   │   │   ├── tenable.json        # • Tenable WAS
│   │   │   ├── openvas.json        # • OpenVAS
│   │   │   ├── cais_tenable.json   # • CAIS Tenable WAS
│   │   │   └── cais_openvas.json   # • CAIS OpenVAS
│   │   └── templates/              # 📝 Templates de prompts
│   │       ├── default_prompt.txt   # • Prompt genérico
│   │       ├── tenable_prompt.txt   # • Tenable WAS otimizado
│   │       ├── openvas_prompt.txt   # • OpenVAS especializado
│   │       └── cais_*.txt          # • Prompts CAIS
│   ├── converters/                 # 🔄 Conversores de formato
│   │   ├── base_converter.py       # • Classe base
│   │   ├── csv_converter.py        # • Exportação CSV
│   │   └── xlsx_converter.py       # • Exportação Excel
│   └── utils/                      # 🛠️ Utilitários core
│       ├── utils.py                # • LLM loading e configuração
│       ├── processing.py           # • Sistema de chunks otimizados
│       ├── scanner_strategies.py   # • Estratégias de scanning
│       └── profile_registry.py     # • Registry de perfis
└── data/                           # 📂 Dados e resultados
    ├── *.pdf                       # • Relatórios de entrada
    ├── vulnerabilities_*.json      # • Resultados JSON
    ├── visual_layout_*.txt         # • Layouts extraídos
    └── exports/                    # • Conversões CSV/XLSX
```

### 🔧 Componentes principais:

- **🎯 main.py**: Interface CLI com parsing de argumentos e orquestração
- **🧮 processing.py**: Sistema de chunking com cálculo otimizado de tokens
- **🤖 utils.py**: Loading de LLMs com configurações customizadas
- **📊 scanner_strategies.py**: Lógica de processamento por tipo de scanner
- **🔄 converters/**: Exportação para múltiplos formatos de saída

##  Licença

Este projeto é fornecido como está, para fins educacionais e de pesquisa.
