# Extrator de PDF para TenableWAS

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.6+-blue.svg" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Vulnerabilidades-Escaneamento-red.svg" alt="Vulnerabilidades">
</div>

## 📋 Sobre

Extrato de PDF TeanableWAS é uma ferramenta especializada para extrair e analisar dados de relatórios de vulnerabilidade do TenableWAS em formato PDF. A ferramenta converte os relatórios em formato JSON estruturado, facilitando a integração com outras ferramentas de análise de segurança e automação de relatórios.

## ✨ Recursos

- ✅ Extração completa do conteúdo de PDFs do TenableWAS
- ✅ Identificação e estruturação de detalhes das vulnerabilidades
- ✅ Extração de informações importantes como nome, severidade, plugin_id, descrições e soluções
- ✅ Detecção de informações de risco (CVSS, CWE, CVE, etc.)
- ✅ Exportação para formato JSON estruturado
- ✅ Interface de linha de comando simples e intuitiva

## 🚀 Instalação

### Pré-requisitos

- Python 3.6 ou superior
- pip (gerenciador de pacotes Python)

### Passos de instalação

1. Clone o repositório:

```bash
git clone https://github.com/AnonShield/pdf_reader_tenableWAS.git
cd "pdf_reader_tenableWAS"
```

2. Execute o script de instalação de dependências:

```bash
python setup_dependencies.py
```

Isso instalará automaticamente todas as dependências necessárias:
- PyPDF2
- pymupdf

## 💻 Como usar

### Uso básico

Execute o script principal com o caminho para o arquivo PDF do TenableWAS:

```bash
python main.py [caminho_para_arquivo_pdf]
```

Se nenhum arquivo for especificado, o programa procurará por PDFs no diretório atual e permitirá que você escolha um.

### Saída

O programa gera um arquivo JSON com o mesmo nome do arquivo PDF de entrada, adicionando o sufixo "_extracted.json". Por exemplo:

```
WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf → WAS_Web_app_scan_Juice_Shop___bWAAP-2[1]_extracted.json
```

## 📊 Estrutura do JSON de saída

O arquivo JSON gerado contém três seções principais:

### Informações do escaneamento
```json
"scan_info": {
    "scan_name": "Nome do escaneamento",
    "scan_date": "Data do escaneamento",
    "contact": "Email de contato"
}
```

### Vulnerabilidades
```json
"vulnerabilities": [
    {
        "name": "Nome da vulnerabilidade",
        "severity": "Severidade (Critical/High/Medium/Low/Info)",
        "plugin_id": "ID do plugin",
        "description": "Descrição detalhada da vulnerabilidade",
        "solution": "Solução recomendada",
        "risk_information": "Informações de risco (CVSS, CWE, CVE, etc.)",
        "family": "Família/categoria da vulnerabilidade"
    },
    ...
]
```

### Metadados de extração
```json
"extracted_at": "Data e hora da extração em formato ISO"
```

## 📝 Exemplo de JSON de saída

```json
{
  "scan_info": {
    "scan_name": "Web app scan Juice Shop & bWAAP",
    "scan_date": "April 26, 2025 at 12:23 (UTC)",
    "contact": "servicedesk@example.com"
  },
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "High",
      "plugin_id": "98115",
      "description": "Due to the requirement for dynamic content of today's web applications...",
      "solution": "Prepare parameterized statements...",
      "risk_information": "CVSSV4 BASE SCORE 7.2\nCVSSV4 VECTOR CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
      "family": "Injection"
    },
    {
      "name": "Missing HTTP Strict Transport Security Policy",
      "severity": "Medium",
      "plugin_id": "98056",
      "description": "The HTTP protocol by itself is clear text...",
      "solution": "Configure the server to include HSTS header...",
      "risk_information": "CVSSV3 BASE SCORE 6.5\nCVSSV3 VECTOR CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
      "family": "HTTP Security Header"
    }
  ],
  "extracted_at": "2025-09-30T15:42:17.123456"
}
```

## 🤝 Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias para o projeto.

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para mais detalhes.

## 📬 Contato

Para questões, sugestões ou suporte, por favor abra uma issue no repositório do projeto ou entre em contato diretamente.

---

<div align="center">
  <sub>Desenvolvido com ❤️ para a comunidade de segurança</sub>
</div>
