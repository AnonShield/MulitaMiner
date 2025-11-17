# 🔍 PDF Vulnerability Extractor

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
- Suporte a múltiplos provedores (OpenAI, Groq, Anthropic, etc.)
- Configuração flexível de parâmetros (temperatura, tokens, endpoints)
- Adaptação para diferentes capacidades de modelos

#### ⚙️ **Perfis de processamento adaptáveis**
- Configuração de tamanho de chunks conforme complexidade do relatório
- Ajuste de sobreposição para diferentes tipos de documentos
- Controle de duplicação e intervalos de processamento
- Personalização de arquivos de saída

#### 📋 **Templates de prompt customizáveis**
- Templates específicos para diferentes ferramentas de segurança
- Formatos de saída flexíveis (JSON estruturado, texto plano)
- Mapeamento de campos específico por ferramenta
- Facilidade para adicionar novos templates para outras ferramentas

#### 🔧 **Como personalizar:**

**Para novos tipos de relatório:**
1. Crie um novo template em `src/configs/templates/`
2. Configure um novo perfil em `src/configs/profile/`
3. Ajuste os parâmetros conforme a estrutura do relatório

**Para novos LLMs:**
1. Configure endpoint e parâmetros em `src/configs/llms/`
2. Ajuste temperatura e tokens conforme capacidades do modelo

**Para novos formatos de saída:**
1. Modifique o template de prompt para o formato desejado
2. Ajuste os conversores em `src/converters/` se necessário

## 📖 Uso

### Sintaxe básica:
```bash
python main.py <caminho_do_pdf> [opções]
```

### Exemplos:

#### Uso básico:
```bash
python main.py relatorio.pdf
```

#### Com perfil personalizado:
```bash
python main.py relatorio.pdf --profile custom_profile
```

#### Com path completo:
```bash
python main.py ".\WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf"
```

#### Ajuda:
```bash
python main.py --help
```

### Opções disponíveis:

| Opção | Descrição |
|-------|-----------|
| `pdf_path` | Caminho para o arquivo PDF (obrigatório) |
| `--profile`, `-p` | Perfil de configuração a usar |
| `--help`, `-h` | Mostra ajuda |

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