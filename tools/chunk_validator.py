"""
Validador automático de chunks - Verificação completa do sistema de chunking

Analisa todos os chunks gerados para garantir:
1. Tamanho adequado para LLM
2. Divisões corretas respeitando estrutura das vulnerabilidades  
3. Integridade dos dados (sem truncamentos)
4. Optimização para melhor qualidade de extração
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from utils.pdf_loader import load_pdf_with_pypdf2
from utils.processing import get_token_based_chunks, split_text_to_subchunks, detect_scanner_pattern
from utils.utils import load_profile, load_llm
import tiktoken
import re


class ChunkValidator:
    def __init__(self, pdf_path: str, profile_name: str = 'default', llm_name: str = 'gpt4'):
        self.pdf_path = pdf_path
        self.profile_config = load_profile(profile_name)
        self.llm_config = load_llm(llm_name)
        
        # CONFIGURAÇÃO SIMPLIFICADA
        if 'max_chunk_size' in self.llm_config:
            self.max_tokens = self.llm_config['max_chunk_size'] + self.llm_config.get('reserve_for_response', 1500)
        else:
            self.max_tokens = self.llm_config.get('max_tokens', 4096)
        
        try:
            self.tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
        except:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
            
        print(f"🔍 Validator: {os.path.basename(pdf_path)} | {profile_name} | {llm_name}")
        print(f"🎯 Max tokens: {self.max_tokens}")
        print(f"{'='*70}")
    
    def load_and_analyze_document(self):
        """Carrega documento e analisa o texto completo"""
        print("📖 Carregando documento...")
        
        # Verificar se é arquivo .txt ou PDF
        if self.pdf_path.endswith('.txt'):
            print("📄 Detectado arquivo de texto (.txt)")
            try:
                with open(self.pdf_path, 'r', encoding='utf-8') as f:
                    text = f.read()
            except Exception as e:
                print(f"❌ Erro ao ler arquivo texto: {e}")
                return None
        else:
            print("📄 Detectado arquivo PDF")
            text = load_pdf_with_pypdf2(self.pdf_path)
        
        if not text:
            print("❌ Erro: Não foi possível carregar o documento")
            return None
            
        print(f"✅ Documento carregado: {len(text):,} caracteres")
        
        # Detectar tipo de scanner
        pattern_info = detect_scanner_pattern(text)
        print(f"🔍 Scanner detectado: {pattern_info['scanner_type'].upper()}")
        print(f"📍 Marcadores encontrados: {pattern_info['markers_found']}")
        print(f"👥 Usa pares BASE+INSTANCES: {pattern_info['has_pairs']}")
        
        return text, pattern_info
    
    def analyze_chunks(self, text: str, pattern_info: dict):
        """Analisa os chunks gerados pelo sistema atual"""
        print(f"\n{'='*70}")
        print("🔧 ANÁLISE DE CHUNKS DO SISTEMA ATUAL")
        print(f"{'='*70}")
        
        # Gerar chunks usando sistema atual
        chunks = get_token_based_chunks(text, self.max_tokens, 
                                       llm_config=self.llm_config,
                                       profile_config=self.profile_config)
        
        print(f"📊 Chunks: {len(chunks)}")
        print(f"📝 ANÁLISE:\n")
        
        issues_found = []
        max_content_tokens = self.max_tokens - 1500  # Reserve para prompt + resposta
        
        for i, chunk in enumerate(chunks, 1):
            token_count = len(self.tokenizer.encode(chunk.page_content))
            markers = self._count_vulnerability_markers(chunk.page_content, pattern_info)
            begins_cleanly = self._check_clean_beginning(chunk.page_content, pattern_info)
            ends_cleanly = self._check_clean_ending(chunk.page_content, pattern_info)
            
            # Status simplificado
            size_ok = token_count <= max_content_tokens
            struct_ok = begins_cleanly and ends_cleanly
            
            print(f"🧩 {i:2d}: {token_count:4d}t, {markers:2d}m, {'✅' if size_ok else '❌'}, {'✅' if struct_ok else '❌'}")
            
            # Coletar problemas
            if not size_ok:
                issues_found.append(f"Chunk {i}: {token_count} tokens > {max_content_tokens}")
            if not begins_cleanly:
                issues_found.append(f"Chunk {i}: Início truncado")
            if not ends_cleanly:
                issues_found.append(f"Chunk {i}: Final truncado")
            if not ends_cleanly:
                issues_found.append(f"Chunk {i}: Final truncado")
        
        print(f"\n📈 Resumo: {len(issues_found)} problemas encontrados")
        return issues_found
    
    def _count_vulnerability_markers(self, text: str, pattern_info: dict) -> int:
        """Conta marcadores de vulnerabilidade no chunk"""
        if not pattern_info['marker_pattern']:
            return 0
        return len(re.findall(pattern_info['marker_pattern'], text, re.MULTILINE))
    
    def _check_clean_beginning(self, text: str, pattern_info: dict) -> bool:
        """Verifica se chunk começa em ponto apropriado"""
        if not pattern_info['marker_pattern']:
            return True  # Se não há padrão, assume OK
        
        lines = text.strip().split('\n')
        if not lines:
            return False
        
        # CORREÇÃO: Para Tenable WAS, precisa encontrar o padrão completo nas primeiras linhas
        # O título da vulnerabilidade pode estar antes do marcador VULNERABILITY [SEVERITY] PLUGIN ID
        
        # Primeira linha não-vazia deve ser um marcador OU estar próxima de um (até 10 linhas)
        for i, line in enumerate(lines[:10]):  # Verifica primeiras 10 linhas
            if re.search(pattern_info['marker_pattern'], line):
                return True
            
        # Se é Tenable WAS e não encontrou o marcador, pode ser título antes do marcador
        if pattern_info['scanner_type'] == 'tenable_was':
            # Verifica se nas primeiras 15 linhas há o padrão
            search_text = '\n'.join(lines[:15])
            if re.search(pattern_info['marker_pattern'], search_text, re.MULTILINE):
                return True
                
        return False
    
    def _check_clean_ending(self, text: str, pattern_info: dict) -> bool:
        """Verifica se chunk termina em ponto apropriado"""
        if not pattern_info['marker_pattern']:
            return True
            
        # Chunk deve terminar completo (não no meio de uma vulnerabilidade)
        lines = text.strip().split('\n')
        if len(lines) < 3:
            return False
            
        # Últimas linhas devem parecer um final completo
        last_lines = '\n'.join(lines[-10:])  # Últimas 10 linhas
        
        # Se há um marcador nas últimas linhas, deve ter conteúdo suficiente após ele
        markers_in_end = re.finditer(pattern_info['marker_pattern'], last_lines, re.MULTILINE)
        markers_list = list(markers_in_end)
        
        if markers_list:
            # Se há marcador muito próximo do final, pode estar truncado
            last_marker_pos = markers_list[-1].start()
            content_after = last_lines[last_marker_pos:]
            return len(content_after) > 100  # Pelo menos 100 chars após último marcador
            
        return True
    
    def _analyze_tenable_pairs(self, text: str) -> str:
        """Analisa pares BASE+INSTANCES para Tenable WAS"""
        # CORREÇÃO: Usar o padrão correto para detectar vulnerabilidades BASE
        base_vulns = re.findall(r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+PLUGIN\s+ID\s+\d+', text, re.MULTILINE)
        instances_vulns = re.findall(r'Instances \(\d+\)', text)
        
        if not base_vulns:
            return "Nenhuma vulnerabilidade BASE encontrada"
        if not instances_vulns:
            return f"{len(base_vulns)} BASE, 0 INSTANCES (possível problema)"
            
        return f"{len(base_vulns)} BASE, {len(instances_vulns)} INSTANCES"
    
    def suggest_improvements(self, issues: list, text: str, pattern_info: dict):
        """Sugere melhorias baseado nos problemas encontrados"""
        if not issues:
            print("✅ Sistema de chunking funcionando adequadamente")
            return
            
        print(f"\n💡 PROBLEMAS ({len(issues)}):")
        size_issues = sum(1 for i in issues if "tokens >" in i)
        structure_issues = sum(1 for i in issues if "truncado" in i)
        
        if size_issues:
            print(f"   • {size_issues} chunks muito grandes")
        if structure_issues:
            print(f"   • {structure_issues} chunks com estrutura problemática")
        
        print("💡 Soluções: Ajustar configurações do scanner em src/configs/scanners/")
        
    def test_alternative_chunking(self, text: str, pattern_info: dict):
        """Testa estratégia alternativa simplificada"""
        print(f"\n🧪 TESTE ALTERNATIVO:")
        max_content_tokens = self.max_tokens - 1500
        chars_per_token = len(text) / len(self.tokenizer.encode(text))
        target_chars = int(max_content_tokens * chars_per_token * 0.9)
        
        alternative_chunks = split_text_to_subchunks(text, target_chars, self.profile_config)
        print(f"Alternativo criaria {len(alternative_chunks)} chunks")
    
    def run_complete_analysis(self):
        """Executa análise simplificada"""
        print("🚀 Analisando chunks...")
        
        # Carregar documento
        result = self.load_and_analyze_document()
        if not result:
            return
        text, pattern_info = result
        
        # Analisar chunks
        issues = self.analyze_chunks(text, pattern_info)
        
        # Resultado final
        self.suggest_improvements(issues, text, pattern_info) 
        self.test_alternative_chunking(text, pattern_info)
        
        status = "✅ OK" if not issues else f"⚠️ {len(issues)} problemas"
        print(f"\n🏁 RESULTADO: {status}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python chunk_validator.py <pdf_path> [profile] [llm]")
        print("Example: python chunk_validator.py report.pdf tenable gpt4")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else 'default'
    llm = sys.argv[3] if len(sys.argv) > 3 else 'gpt4'
    
    validator = ChunkValidator(pdf_path, profile, llm)
    validator.run_complete_analysis()