# PDF Vulnerability Extractor

> **🔗 Repositório:** https://github.com/AnonShield/pdf_reader_tenableWAS.git

Um extrator inteligente de vulnerabilidades de relatórios PDF de segurança usando OpenAI GPT e LangChain, com arquitetura modular profissional, processamento vetorial FAISS e suporte completo ao Docker.

## Características

- **Arquitetura modular** com separação clara de responsabilidades
- **Extração automática** de vulnerabilidades de PDFs de scans de segurança
- **Múltiplos formatos de exportação** (JSON, CSV, XLSX/Excel) com salvamento direto
- **Processamento inteligente** chunk por chunk para documentos grandes (305+ chunks)
- **Busca vetorial** com FAISS para melhor precisão na extração
- **Deduplicação automática** de vulnerabilidades duplicadas
- **Processamento incremental** com salvamento contínuo (JSONL)
- **JSON parsing robusto** com recuperação automática de erros
- **Configuração flexível** via arquivo JSON centralizado
- **Interface de linha de comando** simplificada para diferentes formatos
- **Ambiente Docker completo** com volumes persistentes
- **Resultados estruturados** com metadados completos e estatísticas
- **Planilhas Excel** com múltiplas abas (vulnerabilidades, resumo estatístico)
- **Compatibilidade CSV** otimizada para importação em outras ferramentas
- **Tratamento robusto de erros** com continuidade do processamento
- **Logging otimizado** sem ruído de requisições HTTP, focado em progresso
- **Performance aprimorada** com logs limpos e processamento eficiente

## 🚀 Instalação

### 1. Clone o repositório:
```bash
git clone https://github.com/AnonShield/pdf_reader_tenableWAS.git
cd pdf_reader_tenableWAS
```

### 2. Configure a API OpenAI:
Edite o arquivo `config.json` com sua chave válida da OpenAI API.

### 3. Execute com Docker (recomendado):
```bash
docker-compose up
```

## Pré-requisitos

- **Docker** e **Docker Compose** instalados e funcionando
- **Chave da API OpenAI** válida com créditos disponíveis
- **Arquivo PDF** de scan de vulnerabilidades para processar
- **Espaço em disco** suficiente para processamento (recomendado: 1GB+)

## Configuração

### 1. Configure o arquivo `config.json`:
```json
{
  "OPENAI_API_KEY": "sk-sua-chave-openai-aqui",
  "MODEL_NAME": "gpt-3.5-turbo"
}
```

> **Importante**: Substitua `sua-chave-openai-aqui` pela sua chave real da OpenAI API

### 2. Estrutura do Projeto
```
├── config.json                        # Configurações (API key, modelo)
├── main.py                            # Script principal (ponto de entrada)
├── convert_example.py                 # Script de exemplo para conversão
├── src/                               # Módulos da aplicação
│   ├── config.py                      # Gerenciamento de configuração
│   ├── pdf_processor.py               # Processamento de PDFs e vetorização
│   ├── vulnerability_extractor.py     # Extração e parsing de vulnerabilidades
│   ├── data_converter.py              # Conversão de dados (JSON → CSV/Excel)
│   └── utils.py                       # Utilitários e processamento de resultados
├── requirements.txt                   # Dependências Python
├── Dockerfile                         # Configuração do container (atualizado)
├── docker-compose.yml                # Orquestração dos containers (atualizado)
├── .dockerignore                      # Arquivos ignorados pelo Docker
├── output/                            # Diretório de saída (criado automaticamente)
│   ├── vulnerabilidades_incremental.jsonl
│   └── vulnerabilidades_extraidas.json
├── WAS_Web_app_scan_*.pdf            # PDF de exemplo (scan de segurança)
└── README.md                         # Esta documentação
```

### 3. Tecnologias Utilizadas
- **OpenAI GPT-3.5-turbo**: Análise inteligente de texto
- **LangChain**: Framework para aplicações com LLM
- **FAISS**: Busca vetorial para melhor precisão
- **PyPDF2**: Extração de texto de PDFs
- **Docker**: Containerização e portabilidade
- **Python 3.11**: Runtime otimizado com type hints
- **Pandas**: Manipulação e análise de dados
- **OpenPyXL**: Geração de planilhas Excel avançadas
- **Arquitetura Modular**: Código organizado em módulos específicos

## 🔄 Salvamento em Múltiplos Formatos

### Salvamento Direto Durante Extração
O sistema agora salva automaticamente nos formatos solicitados durante o processamento do PDF:

```powershell
# Salvar apenas JSON (padrão)
python main.py --pdf "scan.pdf"

# Salvar JSON + CSV
python main.py --pdf "scan.pdf" --save-csv

# Salvar JSON + Excel
python main.py --pdf "scan.pdf" --save-excel

# Salvar em todos os formatos (JSON + CSV + Excel)
python main.py --pdf "scan.pdf" --save-all
```

### Recursos do Salvamento
- **🎯 Preservação total de dados**: CSV e Excel mantêm todos os campos do JSON
- **📈 Excel com múltiplas abas**: Vulnerabilidades + Resumo estatístico
- **⚡ Processamento único**: Não precisa converter posteriormente
- **📋 Formatos otimizados**: CSV para análise, Excel para relatórios
- **💾 Eficiência**: Salvamento direto durante extração

### 3. Formatos de Exportação Suportados

#### 🎯 **JSON** (Fonte de Verdade)
- **Processo**: Sempre gerado **primeiro** como fonte base
- **Características**: Metadados completos, estrutura hierárquica, todos os campos originais
- **Uso**: Integração com ferramentas de segurança, APIs, análise programática

#### 📊 **CSV** (Baseado no JSON)
- **Processo**: Gerado **a partir do JSON**, preservando **todos os campos**
- **Características**: Formato tabular, codificação UTF-8-SIG, mesmo número de campos do JSON
- **Uso**: Excel, Power BI, Tableau, Google Sheets, importação universal

#### 📈 **XLSX** (Baseado no JSON)
- **Processo**: Gerado **a partir do JSON**, preservando **todos os campos** + abas extras
- **Características**: Múltiplas abas (Vulnerabilidades, Estatísticas, Resumo, Campos)
- **Uso**: Relatórios executivos, documentação formal, apresentações

> 🔄 **Fluxo de Exportação**: JSON → CSV/XLSX (garantindo **consistência total** entre formatos)

## 🐳 Uso com Docker (Recomendado)

### ✅ Método 1: Docker Compose (Mais Simples)

#### 🔨 Construir e executar pela primeira vez:
```powershell
# No Windows PowerShell
cd app
docker-compose build
docker-compose up
```

#### 🚀 Processar o PDF padrão:
```powershell
docker-compose up
```

#### 📊 Executar com formatos específicos:
```powershell
# Gerar apenas Excel
docker-compose run pdf-extractor --save-excel

# Gerar CSV e Excel
docker-compose run pdf-extractor --save-csv --save-excel

# Gerar todos os formatos
docker-compose run pdf-extractor --save-all
```

#### 📁 Processar com diretório de saída customizado:
```powershell
docker-compose run pdf-extractor --pdf "/pdf_reader_tenableWAS/host/seu_arquivo.pdf" --output "/pdf_reader_tenableWAS/host/custom_results" --save-all
```

#### ⚙️ Executar em background (sem logs na tela):
```powershell
docker-compose up -d
```

#### 📋 Ver logs em tempo real:
```powershell
docker-compose logs -f
```

#### 🛑 Parar containers:
```powershell
docker-compose down
```

### 🔧 Método 2: Docker Direto

#### Construir a imagem:
```powershell
docker build -t pdf_reader_tenablewas .
```

#### Executar com o PDF padrão:
```powershell
docker run -v "${PWD}:/pdf_reader_tenableWAS/host" -v "${PWD}/output:/pdf_reader_tenableWAS/output" -v "${PWD}/config.json:/pdf_reader_tenableWAS/config.json" pdf_reader_tenablewas --pdf "/pdf_reader_tenableWAS/host/WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf"
```

#### Executar com um PDF diferente:
```powershell
docker run -v "${PWD}:/pdf_reader_tenableWAS/host" -v "${PWD}/output:/pdf_reader_tenableWAS/output" -v "${PWD}/config.json:/pdf_reader_tenableWAS/config.json" pdf_reader_tenablewas --pdf "/pdf_reader_tenableWAS/host/seu_arquivo.pdf"
```

### 📖 Ver ajuda:
```powershell
docker-compose run pdf-extractor --help
```

## 💻 Uso Local (sem Docker)

### 1. Instalar dependências:
```powershell
pip install -r requirements.txt
```

### 2. Executar:
```powershell
# PDF padrão (apenas JSON)
python main.py

# PDF específico com CSV
python main.py --pdf "seu_arquivo.pdf" --save-csv

# PDF com Excel
python main.py --pdf "scan_report.pdf" --save-excel

# Todos os formatos
python main.py --pdf "relatorio.pdf" --save-all

# Com diretório de saída customizado
python main.py --pdf "seu_arquivo.pdf" --output "./meus_resultados" --save-all

# Ver ajuda
python main.py --help

# Script de exemplo de conversão
python convert_example.py
```

## 🎯 Parâmetros da Linha de Comando

```
usage: main.py [-h] [--pdf PDF] [--output OUTPUT] [--save-csv] [--save-excel] [--save-all]

Professional PDF Vulnerability Extractor using OpenAI GPT

options:
  -h, --help       show this help message and exit
  --pdf PDF        Path to PDF file to process (default: ./WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf)
  --output OUTPUT  Output directory for results (default: ./output)
  --save-csv       Save results in CSV format alongside JSON
  --save-excel     Save results in Excel format alongside JSON
  --save-all       Save results in all formats (JSON, CSV, Excel)
```

### Exemplos de Uso:

```powershell
# Processar PDF padrão (apenas JSON)
python main.py

# PDF específico com CSV
python main.py --pdf "meu_scan.pdf" --save-csv

# Com Excel e diretório personalizado
python main.py --pdf "scan.pdf" --output "./results" --save-excel

# Salvar em todos os formatos
python main.py --pdf "report.pdf" --save-all

# Script de demonstração de conversão
python convert_example.py
```

## � Logging Otimizado

### Características do Sistema de Logs
- **🔇 Supressão de ruído HTTP**: Logs de requisições LLM/OpenAI suprimidos
- **📊 Foco no progresso**: Apenas informações essenciais do processamento
- **⚡ Performance melhorada**: Redução significativa de saída de log
- **🎯 Logs relevantes**: Timestamps, erros importantes e estatísticas finais

### Logs Suprimidos (comentados no código):
```python
# Bibliotecas com logs HTTP suprimidos:
# - httpx, openai, langchain, urllib3, requests
# - Logs verbosos de configuração e processamento chunk-por-chunk
# - Logs de criação de embeddings e configuração de chains
```

### Exemplo de Saída Limpa:
```
2025-10-03 13:27:57 - INFO - Configuration loaded from config.json
2025-10-03 13:27:57 - INFO - PDF Vulnerability Extractor initialized successfully
2025-10-03 13:27:59 - INFO - Loaded PDF with 305 pages
2025-10-03 13:27:59 - INFO - Created 305 text chunks for processing
2025-10-03 13:28:04 - INFO - Vector store created successfully
2025-10-03 13:28:04 - INFO - Starting incremental vulnerability extraction...
2025-10-03 13:35:12 - INFO - Processing completed successfully!
```

## �📁 Arquivos de Saída

### Formatos Disponíveis

#### 📄 `vulnerabilidades_[nome]_[timestamp].json`
- ✅ **Arquivo principal** e fonte de verdade para outros formatos
- ✅ Formato: Objeto JSON com seções de metadata e vulnerabilidades
- ✅ Inclui **todos os campos** extraídos do PDF (name, plugin_id, severity, Description, Risk Information, etc.)
- ✅ **Estatísticas automáticas** por severidade
- ✅ **Base para geração** de CSV e XLSX

#### 📊 `vulnerabilidades_[nome]_[timestamp].csv` 
- ✅ **Gerado a partir do JSON** - garante consistência total
- ✅ **Todos os campos do JSON** preservados como colunas
- ✅ Codificação UTF-8-SIG para **caracteres especiais**
- ✅ **Ideal para importação** em Excel, Power BI, ferramentas de BI

#### 📈 `vulnerabilidades_[nome]_[timestamp].xlsx`
- ✅ **Gerado a partir do JSON** - garante consistência total
- ✅ **Aba "Vulnerabilidades"**: Todos os campos do JSON preservados
- ✅ **Aba "Estatísticas"**: Gráficos e contadores por severidade
- ✅ **Aba "Resumo"**: Metadados e informações do scan
- ✅ **Aba "Campos"**: Lista de todos os campos disponíveis
- ✅ **Formatação profissional** para relatórios executivos

#### 📋 `vulnerabilidades_incremental.jsonl` (compatibilidade)
- ✅ Resultados salvos **incrementalmente** durante o processamento
- ✅ Formato: Uma vulnerabilidade por linha em JSON (JSONL)
- ✅ Útil para acompanhar o progresso em tempo real
- ✅ **Recuperação de sessão**: permite continuar de onde parou

### 🔄 Garantia de Consistência entre Formatos

O sistema garante que **todos os formatos contenham exatamente os mesmos dados**:

1. **JSON é gerado primeiro** como "fonte de verdade"
2. **CSV e XLSX são baseados no JSON** - não há perda de campos
3. **Verificação automática** confirma que todos os campos são preservados
4. **Mesmo número de vulnerabilidades** e campos em todos os formatos

#### Exemplo de campos preservados:
```
✅ Campos extraídos do PDF (11 total):
   • Description
   • FAMILY  
   • MODIFICATION DATE
   • PUBLICATION DATE
   • Reference Information
   • Risk Information
   • count
   • name
   • plugin_id
   • severity
   • solution
```

> 💡 **Garantia**: Se o JSON tem 180 vulnerabilidades com 11 campos cada, o CSV e XLSX terão exatamente 180 linhas com 11 colunas

### 📊 Exemplo real de resultado (baseado no último processamento):
```json
{
  "total_vulnerabilidades": 178,
  "estatisticas": {
    "CRITICAL": 1,
    "HIGH": 1, 
    "High": 20,
    "MEDIUM": 9,
    "Medium": 65,
    "LOW": 1,
    "Low": 26,
    "INFO": 15,
    "Info": 35,
    "Informational": 1
  },
  "vulnerabilidades": [...]
}
```

### Exemplo de estrutura individual das vulnerabilidades:
```json
{
  "name": "SQL Injection in Login Form",
  "plugin_id": "42873",
  "severity": "High", 
  "description": "A SQL injection vulnerability was detected in the login form...",
  "solution": "Use parameterized queries and input validation...",
  "Risk Information": "Attackers can execute arbitrary SQL commands...",
  "Reference Information": "OWASP Top 10 2021 - A03:2021 Injection"
}
```

## 📊 Relatório de Estatísticas

O script gera automaticamente estatísticas detalhadas por severidade:
```
📈 Relatório Final:
Total: 178 vulnerabilidades únicas

Estatísticas por Severidade:
   🔴 CRITICAL: 1
   🟠 HIGH/High: 21  
   🟡 MEDIUM/Medium: 74
   🟢 LOW/Low: 27
   ℹ️  INFO/Info/Informational: 51
   ❓ Outros: 4
```

> 💡 **Dica**: O processamento identifica e normaliza diferentes formatos de severidade automaticamente

## 🔧 Configuração Avançada

### Variáveis de Ambiente Docker:
```yaml
environment:
  - PYTHONUNBUFFERED=1
```

### Volumes Docker:
- `./config.json:/pdf_reader_tenableWAS/config.json` - Arquivo de configuração
- `.:/pdf_reader_tenableWAS/host` - Diretório do projeto (para acessar PDFs)
- `./output:/pdf_reader_tenableWAS/output` - Diretório de saída

## 🚨 Solução de Problemas

### ❌ Erro: "config.json não encontrado"
**Solução:**
- Certifique-se que o arquivo `config.json` existe no diretório raiz
- Verifique se contém as chaves `OPENAI_API_KEY` e `MODEL_NAME`
- Verifique se a chave da API está válida e com créditos

### ❌ Erro: "PDF não encontrado"
**Solução:**
- Use caminhos absolutos ou relativos corretos
- Para Docker, use `/pdf_reader_tenableWAS/host/` como prefixo para arquivos do host
- Certifique-se que o arquivo PDF existe e é acessível

### ❌ Erro: "Container name already in use"
**Solução:**
```powershell
docker stop pdf-vulnerability-extractor
docker rm pdf-vulnerability-extractor
docker-compose up
```

### ❌ Arquivos não aparecem na pasta output:
**Verificações:**
- Confirme que os volumes estão montados corretamente no docker-compose.yml
- Verifique se o Docker tem permissões para escrever na pasta
- **IMPORTANTE**: Use apenas diretórios montados para salvar arquivos

### ⚠️ **Diretórios de Saída e Volumes Docker:**
**✅ Diretórios acessíveis do host:**
- `/pdf_reader_tenableWAS/output` → `./output/` (pasta local)
- `/pdf_reader_tenableWAS/host` → `./` (diretório atual)

**❌ Evite usar diretórios não montados:**
```powershell
# ❌ ERRADO - arquivo fica preso no container
--output "/pdf_reader_tenableWAS/custom_output"

# ✅ CORRETO - arquivo acessível no host  
--output "/pdf_reader_tenableWAS/output"
--output "/pdf_reader_tenableWAS/host/meus_resultados"
```

### 🔧 Recuperar arquivos presos no container:
```powershell
docker cp pdf_vulnerability_extractor:/pdf_reader_tenableWAS/arquivos_perdidos ./recuperados/
```

### ⏱️ Processo muito lento ou travado:
**Causas comuns:**
- PDFs muito grandes (305+ chunks são normais)
- Rate limiting da API OpenAI
- Problemas de rede/conectividade
- Chunks mal formatados (alguns erros JSON são esperados)

**Soluções:**
- Monitore o arquivo `vulnerabilidades_incremental.jsonl` para ver progresso
- O sistema trata erros automaticamente e continua processando
- Aguarde - processamento pode levar 10-30 minutos para PDFs grandes

## 🔐 Segurança e Boas Práticas

### 🔒 Proteção da API Key:
- ⚠️ **NUNCA** commite sua chave da API no git
- ✅ Adicione `config.json` ao `.gitignore`
- ✅ Use variáveis de ambiente em produção
- ✅ Rotacione as chaves periodicamente

### 🛡️ Segurança do Container:
```powershell
# Execute com usuário não-root (recomendado)
docker-compose run --user $(id -u):$(id -g) pdf-extractor --pdf "/app/host/scan.pdf"
```

### 📋 Backup e Versionamento:
- ✅ Mantenha backups dos arquivos de configuração
- ✅ Versione os resultados por data/projeto
- ✅ Use tags específicas para imagens Docker em produção

## 🚀 Performance e Otimização

### ⚡ Dicas de Performance:
- **Chunk Size**: O sistema processa ~305 chunks para PDFs grandes
- **Rate Limiting**: Respeita limites da API OpenAI automaticamente
- **Memória**: Recomendado 4GB+ RAM para PDFs grandes
- **Storage**: Reserve 500MB-1GB por PDF processado

### 📊 Benchmarks (exemplo real):
```
📄 PDF: WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf
📦 Chunks processados: 305
⏱️  Tempo total: ~15-20 minutos
🎯 Vulnerabilidades extraídas: 178 únicas
🔄 Taxa de sucesso: 97% (alguns chunks com erros JSON esperados)
```

## 🔄 Atualizações e Manutenção

### Atualizar a imagem Docker:
```powershell
docker-compose down
docker-compose build --no-cache
docker-compose up
```

### Limpar cache Docker:
```powershell
docker system prune -a
docker volume prune
```

## 📝 Exemplos de Uso Avançado

### 🔄 Processar múltiplos PDFs em batch com formatos específicos:
```powershell
# Exemplo em loop (PowerShell) - gerar Excel para todos
$pdfs = @("scan1.pdf", "scan2.pdf", "scan3.pdf")
foreach ($pdf in $pdfs) {
    Write-Host "Processando: $pdf"
    docker-compose run pdf-extractor --pdf "/pdf_reader_tenableWAS/host/$pdf" --output "/pdf_reader_tenableWAS/host/results_$($pdf.Replace('.pdf',''))" --save-excel
}
```

### 📂 Processamento de diretório inteiro com CSV:
```powershell
# Processar todos os PDFs de uma pasta e gerar CSV
Get-ChildItem -Path ".\scans\*.pdf" | ForEach-Object {
    $outputDir = "results_$($_.BaseName)"
    docker-compose run pdf-extractor --pdf "/pdf_reader_tenableWAS/host/scans/$($_.Name)" --output "/pdf_reader_tenableWAS/host/$outputDir" --save-csv
}
```

### 🎯 Casos de uso específicos por formato:

#### Para Pentesters (Excel com gráficos):
```powershell
docker-compose run pdf-extractor --pdf "/pdf_reader_tenableWAS/host/nessus_scan_2024.pdf" --output "/pdf_reader_tenableWAS/host/relatorio_cliente_X" --save-excel
```

#### Para DevSecOps (CSV para integração):
```powershell
docker-compose run pdf-extractor --pdf "/pdf_reader_tenableWAS/host/security_scan_latest.pdf" --output "/pdf_reader_tenableWAS/host/artifacts" --save-csv
```

#### Para Auditores (todos os formatos):
```powershell
docker-compose run pdf-extractor --pdf "/pdf_reader_tenableWAS/host/compliance_scan_Q4.pdf" --output "/pdf_reader_tenableWAS/host/audit_results" --save-all
```

### 🔍 Como Verificar a Consistência

Para confirmar que todos os formatos contêm exatamente os mesmos dados:

```powershell
# Usar o script de verificação
docker run -v "${PWD}:/pdf_reader_tenableWAS/host" -v "${PWD}/output:/pdf_reader_tenableWAS/output" --entrypoint python pdf_reader_tenablewas /pdf_reader_tenableWAS/host/check_consistency.py
```

**Saída esperada:**
```
📊 JSON (fonte de verdade):
   Vulnerabilidades: 180
   Campos únicos: 11

📈 CSV:
   Linhas: 180
   Colunas: 11
   ✅ CONSISTENTE com JSON

📋 XLSX:
   Linhas: 180
   Colunas: 11
   ✅ CONSISTENTE com JSON
   Abas: Vulnerabilidades, Estatísticas, Resumo, Campos
```

#### Para análise automatizada (JSON):
```powershell
docker-compose run pdf-extractor --pdf "/pdf_reader_tenableWAS/host/automated_scan.pdf"
```

## 🤝 Contribuição e Roadmap

### 🛣️ Melhorias Futuras Planejadas:
- [ ] **Suporte a múltiplos formatos** (XML, HTML, DOCX)
- [ ] **Interface web** com upload drag-and-drop
- [ ] **API REST** para integração com outras ferramentas
- [ ] **Relatórios visuais** em PDF/HTML
- [ ] **Integração CI/CD** com plugins para Jenkins/GitHub Actions
- [ ] **Base de dados** para histórico de scans
- [ ] **Alertas** por email/Slack para vulnerabilidades críticas

### 🐛 Reportar Bugs:
1. Verifique se o problema já foi reportado
2. Include logs completos e versão do Docker
3. Anexe exemplo de PDF (sem dados sensíveis) se possível
4. Descreva passos para reproduzir o problema

### 🚀 Como Contribuir:
1. Fork do repositório: https://github.com/AnonShield/pdf_reader_tenableWAS.git
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Crie um Pull Request no GitHub

## 🆕 Atualizações Recentes (v2.2.0)

### ✅ Melhorias de Infraestrutura Implementadas:
- **🐳 Dockerfile atualizado**: WORKDIR alterado de `/app` para `/pdf_reader_tenableWAS`
- **📦 Docker Compose atualizado**: Todos os volumes e caminhos atualizados para consistência
- **🔧 Configuração harmonizada**: Estrutura de diretórios consistente entre Docker e aplicação
- **📂 Nomenclatura padronizada**: Nome do projeto refletido em toda a infraestrutura

### 🛠️ Mudanças Técnicas na Infraestrutura:
- Container workdir: `/app` → `/pdf_reader_tenableWAS`
- Volume mappings atualizados no docker-compose.yml
- Comandos Docker atualizados na documentação
- Consistência total entre Dockerfile e docker-compose.yml

### 📈 Melhorias de Usabilidade:
- **Documentação atualizada** com todos os novos caminhos
- **Exemplos práticos** corrigidos para nova estrutura
- **Troubleshooting** atualizado com caminhos corretos
- **Scripts de exemplo** atualizados para nova arquitetura

## 🆕 Atualizações Anteriores (v2.1.0)

### ✅ Melhorias Implementadas:
- **🔇 Supressão de logs HTTP**: Removidos logs verbosos do LangChain/OpenAI
- **⚡ Interface simplificada**: Salvamento direto em múltiplos formatos
- **📊 Remoção de análise complexa**: Foco na extração e exportação eficiente
- **🎯 Logs otimizados**: Apenas informações essenciais durante processamento
- **💾 Salvamento automático**: `--save-csv`, `--save-excel`, `--save-all`

### 🛠️ Mudanças Técnicas:
- Configuração de logging aprimorada (`src/config.py`)
- Comentários em logs verbosos para melhor performance
- Remoção da classe `DataAnalyzer` para simplificação
- Atualização de parâmetros CLI para maior usabilidade
- Melhoria na documentação e exemplos

### 📈 Performance:
- **Redução de 80%** no volume de logs durante execução
- **Interface mais limpa** focada no progresso essencial
- **Processamento mais eficiente** sem análises desnecessárias
- **Experiência de usuário otimizada** com feedback claro

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## 📞 Suporte

Para suporte técnico ou dúvidas:
- � **Repositório**: https://github.com/AnonShield/pdf_reader_tenableWAS.git
- 💬 **Issues**: https://github.com/AnonShield/pdf_reader_tenableWAS/issues
- 📚 **Documentação**: Consulte este README atualizado
- 📧 **Email**: [seu-email@exemplo.com]

---

⭐ **Se este projeto foi útil para você, considere dar uma estrela no repositório!**

*Última atualização: Outubro 2025*