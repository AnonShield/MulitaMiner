# Dockerfile para MulitaMiner - Extrator de Vulnerabilidades PDF
FROM python:3.11-slim

# Definir diretório de trabalho
WORKDIR /app

# Instalar dependências do sistema necessárias para PDF processing
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements primeiro para melhor cache do Docker
COPY requirements.txt .

# Instalar dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Invalidar cache para garantir que código seja sempre atualizado
ADD "https://www.random.org/cgi-bin/randbyte?nbytes=10&format=h" skipcache

# Copiar todo o código fonte
COPY . .

# Criar diretórios necessários se não existirem
RUN mkdir -p data pdfs jsons metrics

# Definir variáveis de ambiente
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expor porta (caso seja usado algum servidor web no futuro)
EXPOSE 8080

# Comando padrão - mostra ajuda do programa
CMD ["python", "main.py", "--help"]