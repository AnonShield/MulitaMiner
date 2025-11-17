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

### 1. Arquivo config.json

Crie ou edite o arquivo `config.json` com suas configurações:

```json
{
  "api_key": "sua_api_key_aqui",
  "endpoint": "https://api.groq.com/openai/v1",
  "model": "llama-3.1-8b-instant",
  "temperature": 0,
  "max_tokens": null,
  "chunk_size": 1500,
  "chunk_overlap": 150,
  "output_file": "vulnerabilities.json"
}
```

### 2. Configurações disponíveis:

| Campo | Descrição | Exemplo |
|-------|-----------|---------|
| `api_key` | Chave da API do provedor | `"gsk_xxx..."` |
| `endpoint` | URL do endpoint da API | `"https://api.groq.com/openai/v1"` |
| `model` | Nome do modelo a usar | `"llama-3.1-8b-instant"` |
| `temperature` | Criatividade do modelo (0-1) | `0` |
| `max_tokens` | Limite de tokens por resposta | `null` |
| `chunk_size` | Tamanho dos chunks de texto | `1500` |
| `chunk_overlap` | Sobreposição entre chunks | `150` |
| `output_file` | Nome do arquivo de saída | `"vulnerabilities.json"` |

### 3. Provedores suportados:

#### Groq (Recomendado - Gratuito e rápido)
```json
{
  "endpoint": "https://api.groq.com/openai/v1",
  "model": "llama-3.1-8b-instant"
}
```

**Modelos Groq disponíveis:**
- `llama-3.1-70b-versatile` (mais inteligente)
- `llama-3.1-8b-instant` (rápido)
- `mixtral-8x7b-32768` (alternativa)
- `gemma2-9b-it` (Google)

#### OpenAI
```json
{
  "endpoint": "https://api.openai.com/v1",
  "model": "gpt-3.5-turbo"
}
```

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

#### Com arquivo de configuração personalizado:
```bash
python main.py relatorio.pdf --config meu_config.json
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
| `--config`, `-c` | Arquivo de configuração JSON (padrão: config.json) |
| `--help`, `-h` | Mostra ajuda |

## 📄 Formato de saída

A ferramenta gera um arquivo JSON com as vulnerabilidades encontradas:

```json
[
  {
    "name": "SQL Injection",
    "plugin_id": "9",
    "Description": "The web application is vulnerable to SQL injection attacks.",
    "severity": "High",
    "solution": "Implement proper input validation and sanitization.",
    "Risk Information": "An attacker can exploit this vulnerability to gain unauthorized access.",
    "Reference Information": "https://owasp.org/www-community/attacks/SQL_Injection"
  }
]
```

## 🔧 Resolução de problemas

### Erro: "modelo descontinuado"
```
ERRO: O modelo 'llama3-8b-8192' foi descontinuado!
```
**Solução:** Atualize o modelo no `config.json` para um modelo válido.

### Erro: "arquivo não encontrado"
```
Erro: Arquivo PDF não encontrado: arquivo.pdf
```
**Solução:** Verifique se o caminho do PDF está correto e o arquivo existe.

### Erro: "API key inválida"
```
Erro: 401 - Unauthorized
```
**Solução:** Verifique se a API key no `config.json` está correta.

### Erro: "limite de quota"
```
Limite de quota atingido no chunk X
```
**Solução:** Aguarde ou use um provedor diferente (ex: Groq gratuito).

## 📁 Estrutura do projeto

```
pdf-vulnerability-extractor/
├── main.py              # Script principal
├── config.json          # Configurações
├── requirements.txt     # Dependências
├── README.md           # Este arquivo
└── vulnerabilities.json # Saída (gerado após execução)
```

## 🚀 Exemplo completo

1. **Configurar API key no config.json:**
```json
{
  "api_key": "gsk_sua_chave_aqui",
  "endpoint": "https://api.groq.com/openai/v1",
  "model": "llama-3.1-8b-instant",
  "temperature": 0,
  "max_tokens": null,
  "chunk_size": 1500,
  "chunk_overlap": 150,
  "output_file": "vulnerabilities.json"
}
```

2. **Executar a ferramenta:**
```bash
python main.py "WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf"
```

3. **Resultado:**
```
Arquivo PDF: WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf
Usando modelo: llama-3.1-8b-instant
Endpoint: https://api.groq.com/openai/v1
Carregando o PDF...
Dividindo o texto em chunks...
Processando todo o texto para extrair vulnerabilidades...
Processando chunk 1/386...
  Encontradas 2 vulnerabilidades no chunk 1
...
=== PROCESSAMENTO CONCLUÍDO ===
Total original de vulnerabilidades: 470
Duplicatas removidas: 15
Vulnerabilidades únicas salvas: 455
Arquivo salvo: vulnerabilities.json
```
## 📝 Licença

Este projeto é fornecido como está, para fins educacionais e de pesquisa.