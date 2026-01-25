#!/usr/bin/env python3
"""
Script de teste específico para Tenable WAS - debugging
"""
import sys
import os
import json

# Adicionar src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from utils.utils import load_profile, load_llm, init_llm
from utils.processing import get_token_based_chunks, build_prompt, TokenChunk
from utils.cais_validator import validate_cais_vulnerability
from utils.processing import parse_json_response

def test_tenable_processing():
    """Teste direto do processamento Tenable WAS"""
    
    # 1. Carregar configurações
    print("[TEST] Carregando configurações...")
    profile_config = load_profile('tenable')
    llm_config = load_llm('llama3')
    llm = init_llm(llm_config)
    
    print(f"[TEST] Profile: {profile_config}")
    print(f"[TEST] LLM: {llm_config}")
    
    # 2. Carregar conteúdo do arquivo de teste
    file_path = "visual_layout_extracted_TenableWAS_bWAAP.txt"
    
    print(f"[TEST] Carregando arquivo: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        except Exception as e:
            print(f"[TEST ERROR] Falha ao carregar arquivo: {e}")
            return
    
    print(f"[TEST] Arquivo carregado - {len(content)} caracteres")
    
    # 3. Criar chunks
    print(f"[TEST] Criando chunks...")
    chunks = get_token_based_chunks(content, llm_config.get('max_tokens', 8192), 
                                   llm_config.get('reserve_for_response', 1000), llm_config)
    
    print(f"[TEST] Criados {len(chunks)} chunks")
    
    # 4. Testar primeiro chunk
    if chunks:
        chunk = chunks[0]
        print(f"[TEST] Testando chunk 1 - {len(chunk.page_content)} caracteres")
        
        # Construir prompt
        prompt = build_prompt(chunk, profile_config)
        print(f"[TEST] Prompt construído - {len(prompt)} caracteres")
        
        # Debug: mostrar início do chunk
        print(f"[TEST] Início do chunk: {chunk.page_content[:200]}...")
        
        # Invocar LLM
        print(f"[TEST] Invocando LLM...")
        try:
            response = llm.invoke(prompt).content
            print(f"[TEST] Resposta recebida - {len(response)} caracteres")
            
            # Debug: mostrar início da resposta
            print(f"[TEST] Início da resposta: {response[:300]}...")
            
            # Debug: salvar resposta completa para análise
            with open("debug_response.json", "w", encoding="utf-8") as f:
                f.write(response)
            print(f"[TEST] Resposta completa salva em debug_response.json")
            
            # Parse JSON
            print(f"[TEST] Fazendo parse JSON...")
            vulnerabilities = parse_json_response(response, "teste")
            
            if vulnerabilities:
                print(f"[TEST] ✅ JSON válido - {len(vulnerabilities)} vulnerabilidades")
                
                # Testar validação CAIS
                valid_vulns = []
                for i, vuln in enumerate(vulnerabilities):
                    print(f"[TEST] Validando vulnerabilidade {i+1}:")
                    print(f"  Nome: {vuln.get('definition.name', vuln.get('Name', 'SEM_NOME'))}")
                    print(f"  Campos: {list(vuln.keys())}")
                    
                    validated = validate_cais_vulnerability(vuln)
                    if validated:
                        valid_vulns.append(validated)
                        print(f"[TEST] ✅ Vulnerabilidade {i+1} válida")
                    else:
                        print(f"[TEST] ❌ Vulnerabilidade {i+1} rejeitada")
                        # Mostrar campos que podem estar causando problema
                        required_fields = ["definition.name"]
                        missing = [f for f in required_fields if not vuln.get(f)]
                        if missing:
                            print(f"    Campos obrigatórios faltando: {missing}")
                        else:
                            print(f"    Campos obrigatórios OK - problema pode ser em outro lugar")
                
                print(f"[TEST] RESULTADO FINAL: {len(valid_vulns)}/{len(vulnerabilities)} vulnerabilidades válidas")
                
                if valid_vulns:
                    print(f"[TEST] Exemplo de vulnerabilidade válida:")
                    print(json.dumps(valid_vulns[0], indent=2, ensure_ascii=False))
                
            else:
                print(f"[TEST] ❌ JSON inválido ou vazio")
                
        except Exception as e:
            print(f"[TEST ERROR] Erro na invocação do LLM: {e}")
    else:
        print(f"[TEST ERROR] Nenhum chunk criado")

if __name__ == "__main__":
    test_tenable_processing()