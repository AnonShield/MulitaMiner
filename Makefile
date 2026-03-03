# =================================================================
# MulitaMiner - Makefile for Docker Operations
# =================================================================

.PHONY: help build up down logs shell clean backup test process

# Default target
.DEFAULT_GOAL := help

# Colors for output
GREEN := \033[0;32m
BLUE := \033[0;34m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Variables
IMAGE_NAME := mulitaminer
CONTAINER_NAME := mulitaminer
BACKUP_DIR := backups

help: ## Mostra esta mensagem de ajuda
	@echo "MulitaMiner - Docker Management"
	@echo "================================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

setup: ## Configura o ambiente (cria .env se não existir)
	@echo "Configurando ambiente..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Arquivo .env criado. Configure suas API keys!"; \
	else \
		echo "Arquivo .env já existe"; \
	fi
	@mkdir -p pdfs data results jsons metrics $(BACKUP_DIR)
	@echo "Diretórios criados"

build: ## Constrói a imagem Docker
	@echo "Construindo imagem Docker..."
	docker-compose build
	@echo "Imagem construída com sucesso"

rebuild: ## Reconstrói a imagem Docker do zero
	@echo "Reconstruindo imagem Docker..."
	docker-compose build --no-cache
	@echo "Imagem reconstruída com sucesso"

up: ## Inicia o container
	@echo "Iniciando container..."
	docker-compose up -d
	@echo "Container iniciado"

down: ## Para e remove o container
	@echo "Parando container..."
	docker-compose down
	@echo "Container parado"

restart: ## Reinicia o container
	@echo "Reiniciando container..."
	docker-compose restart
	@echo "Container reiniciado"

logs: ## Mostra os logs do container
	@echo "Mostrando logs..."
	docker-compose logs -f

shell: ## Abre shell interativo no container
	@echo "Abrindo shell interativo..."
	docker-compose exec $(CONTAINER_NAME) bash

status: ## Mostra status dos containers
	@echo "Status dos containers:"
	@docker-compose ps

clean: ## Remove containers, volumes e imagens não utilizadas
	@echo "Limpando recursos Docker..."
	docker-compose down -v --remove-orphans
	docker image prune -f
	docker volume prune -f
	@echo "Limpeza concluída"

backup: ## Cria backup dos dados
	@echo "Criando backup..."
	@mkdir -p $(BACKUP_DIR)
	@tar -czf $(BACKUP_DIR)/mulitaminer_backup_$$(date +%Y%m%d_%H%M%S).tar.gz \
		data/ results/ jsons/ metrics/ 2>/dev/null || true
	@echo "Backup criado em $(BACKUP_DIR)/"

test: ## Testa se o ambiente está funcionando
	@echo "$(BLUE)🧪 Testando ambiente...$(NC)"
	@if docker-compose run --rm $(CONTAINER_NAME) python -c "import sys; print('✅ Python OK'); sys.exit(0)"; then \
		echo "$(GREEN)✅ Teste básico passou$(NC)"; \
	else \
		echo "$(RED)❌ Teste básico falhou$(NC)"; \
	fi

check-env: ## Verifica variáveis de ambiente
	@echo "$(BLUE)🔐 Verificando API keys...$(NC)"
	@docker-compose run --rm $(CONTAINER_NAME) bash -c " \
		echo 'API Keys configuradas:'; \
		env | grep -E 'API_KEY_.*=' | sed 's/=.*/=***HIDDEN***/' || echo 'Nenhuma API key encontrada'" \
	|| echo "$(YELLOW)⚠️  Container não está rodando$(NC)"

# Comandos de processamento
process-help: ## Mostra ajuda do MulitaMiner
	docker-compose run --rm $(CONTAINER_NAME) python main.py --help

process: ## Processa um PDF (uso: make process PDF=/path/to/file.pdf LLM=gpt4 SCANNER=openvas)
	@if [ -z "$(PDF)" ]; then \
		echo "Erro: Especifique o PDF com PDF=/path/to/file.pdf"; \
		exit 1; \
	fi
	@echo "Processando PDF: $(PDF)"
	docker-compose run --rm $(CONTAINER_NAME) python main.py $(PDF) \
		--LLM $(or $(LLM),gpt4) \
		--scanner $(or $(SCANNER),openvas) \
		--convert $(or $(FORMAT),json)

process-all: ## Processa todos os PDFs na pasta pdfs/
	@echo "Processando todos os PDFs..."
	docker-compose run --rm $(CONTAINER_NAME) bash -c " \
		for pdf in /app/pdfs/*.pdf; do \
			if [ -f \"$$pdf\" ]; then \
				echo 'Processando:' \"$$pdf\"; \
				python main.py \"\$$pdf\" --LLM gpt4 --scanner openvas --convert json; \
			fi; \
		done"

# Health checks
health: ## Verifica saúde do container
	@echo "Verificando saúde do container..."
	@if docker inspect $(CONTAINER_NAME) >/dev/null 2>&1; then \
		docker inspect $(CONTAINER_NAME) | grep -A10 '"Health"' || echo "Health check não configurado"; \
	else \
		echo "Container não encontrado"; \
	fi

stats: ## Mostra estatísticas de uso de recursos
	@echo "Estatísticas do container:"
	@docker stats $(CONTAINER_NAME) --no-stream || echo "Container não está rodando"

# Development commands
dev-up: ## Inicia em modo desenvolvimento (com bind mounts)
	@echo "Iniciando em modo desenvolvimento..."
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

dev-logs: ## Logs em modo desenvolvimento
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f

# Update commands
update: ## Atualiza o container (rebuild + restart)
	@echo "Atualizando container..."
	@make down
	@make rebuild
	@make up
	@echo "Container atualizado"

# Exemplo de uso
example: ## Exemplo completo de uso
	@echo "Exemplo de uso:"
	@echo "1. Configure o ambiente: make setup"
	@echo "2. Construa a imagem: make build"
	@echo "3. Inicie o container: make up"
	@echo "4. Processe um PDF: make process PDF=/app/pdfs/report.pdf LLM=gpt4"
	@echo "5. Veja os logs: make logs"