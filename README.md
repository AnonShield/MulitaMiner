# 🔍 Vulnerability Extractor

Uma ferramenta CLI para extrair vulnerabilidades de relatórios PDF de segurança usando LLMs (Large Language Models).

## 📋 Descrição

Esta ferramenta processa relatórios PDF de segurança e extrai vulnerabilidades estruturadas em formato JSON usando modelos de IA. Suporta diferentes provedores de LLM como OpenAI, Groq, e outros compatíveis com a API OpenAI.

## ✨ Funcionalidades

- ✅ Extração automática de vulnerabilidades de PDFs
- ✅ Remoção de duplicatas baseada no nome da vulnerabilidade
- ✅ Suporte a múltiplos provedores de LLM (OpenAI, Groq, etc.)
- ✅ Configuração via arquivo JSON
- ✅ Interface de linha de comando (CLI)
- ✅ Processamento em chunks para documentos grandes
- ✅ Tratamento robusto de erros

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

#### ⚙️ **Perfis de processamento adaptáveis**

Os perfis controlam como o documento é processado e as vulnerabilidades são extraídas.

**Como criar um novo perfil:**

1. **Crie um arquivo de perfil** em `src/configs/profile/`:
```json
// src/configs/profile/nessus.json
{
  "reader": "nessus",
  "prompt_template": "src/configs/templates/nessus_prompt.txt",
  "retry_attempts": 3,
  "delay_between_chunks": 5,
  "remove_duplicates": true,
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

## 📖 Uso

### Sintaxe completa:
```bash
python main.py <pdf_path> [opções]
```

### Argumentos obrigatórios:
- `pdf_path` - Caminho para o arquivo PDF a ser processado

### Opções de configuração:

| Opção | Descrição | Padrão | Exemplo |
|-------|-----------|--------|---------|
| `--profile` | Perfil de configuração a usar | `default` | `--profile openvas` |
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

#### Com perfil específico:
```bash
python main.py relatorio.pdf --profile openvas
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

#### Processamento em lote (múltiplos perfis):
```bash
# OpenVAS
python main.py relatorio_openvas.pdf --profile openvas --convert all

# Tenable
python main.py relatorio_tenable.pdf --profile tenable --convert csv

# Nessus (customizado)
python main.py relatorio_nessus.pdf --profile nessus --LLM gpt4
```

### Fluxo de arquivos:

1. **Entrada**: PDF especificado em `pdf_path`
2. **Processamento**: Usando perfil e LLM configurados
3. **Saída primária**: JSON conforme `output_file` do perfil
4. **Conversões**: Formatos adicionais conforme `--convert`
5. **Layout visual**: Arquivo `.txt` com layout preservado (mesmo diretório do PDF)

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

### Erro: "modelo descontinuado"
```
ERRO: O modelo 'llama3-8b-8192' foi descontinuado!
```
**Solução:** Atualize o modelo nas configurações de LLM para um modelo válido.

### Erro: "arquivo não encontrado"
```
Erro: Arquivo PDF não encontrado: arquivo.pdf
```
**Solução:** Verifique se o caminho do PDF está correto e o arquivo existe.

### Erro: "API key inválida"
```
Erro: 401 - Unauthorized
```
**Solução:** Verifique se a API key nas configurações está correta.

### Erro: "limite de quota"
```
Limite de quota atingido no chunk X
```
**Solução:** Aguarde ou use um provedor diferente (ex: Groq gratuito).

## 📁 Estrutura do projeto

```
pdf-vulnerability-extractor/
├── main.py              # Script principal
├── requirements.txt     # Dependências
├── README.md           # Este arquivo
├── src/                 # Código fonte modular
│   ├── configs/         # Configurações (LLMs, perfis, templates)
│   ├── converters/      # Conversores de saída
│   └── utils/           # Utilitários de processamento
└── data/               # Dados de entrada e saída
```

##  Licença

Este projeto é fornecido como está, para fins educacionais e de pesquisa.
