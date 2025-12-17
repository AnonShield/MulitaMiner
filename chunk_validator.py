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
        
        # USAR CONFIGURAÇÃO DIRETA DO DEEPSEEK
        if 'max_chunk_size' in self.llm_config:
            # Usar configuração específica do LLM
            chars_per_token = 3.2  # Estimativa conservadora
            max_chunk_tokens = self.llm_config['max_chunk_size']
            self.max_tokens = max_chunk_tokens + self.llm_config.get('reserve_for_response', 1500)
        else:
            # Fallback para configuração padrão
            self.max_tokens = self.llm_config.get('max_tokens', 4096)
        
        try:
            self.tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
        except:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
            
        print(f"🔍 Chunk Validator inicializado")
        print(f"📄 PDF: {os.path.basename(pdf_path)}")
        print(f"⚙️  Profile: {profile_name}")
        print(f"🧠 LLM: {llm_name} (max_tokens: {self.max_tokens})")
        
        if 'max_chunk_size' in self.llm_config:
            print(f"🎯 Chunk size configurado: {self.llm_config['max_chunk_size']} tokens")
        
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
                                       llm_config=self.llm_config)
        
        print(f"📊 Total de chunks gerados: {len(chunks)}")
        print(f"\n📝 ANÁLISE DETALHADA DOS CHUNKS:\n")
        
        issues_found = []
        
        for i, chunk in enumerate(chunks, 1):
            print(f"🧩 CHUNK {i}/{len(chunks)}")
            print(f"{'─'*50}")
            
            # Análise básica
            char_count = len(chunk.page_content)
            token_count = len(self.tokenizer.encode(chunk.page_content))
            
            print(f"📏 Tamanho: {char_count:,} caracteres, ~{token_count:,} tokens")
            
            # Verificar se está dentro dos limites
            max_content_tokens = self.max_tokens - 1500  # Reserve para prompt + resposta
            status = "✅ OK" if token_count <= max_content_tokens else "⚠️  MUITO GRANDE"
            print(f"🎯 Status de tamanho: {status}")
            
            if token_count > max_content_tokens:
                issues_found.append(f"Chunk {i}: {token_count} tokens > {max_content_tokens} (limite)")
            
            # Análise de estrutura
            markers = self._count_vulnerability_markers(chunk.page_content, pattern_info)
            print(f"🏷️  Marcadores de vulnerabilidade: {markers}")
            
            # Verificar início e fim
            begins_cleanly = self._check_clean_beginning(chunk.page_content, pattern_info)
            ends_cleanly = self._check_clean_ending(chunk.page_content, pattern_info)
            
            print(f"🟢 Início limpo: {'✅' if begins_cleanly else '❌'}")
            print(f"🔚 Final limpo: {'✅' if ends_cleanly else '❌'}")
            
            if not begins_cleanly:
                issues_found.append(f"Chunk {i}: Início truncado ou incompleto")
            if not ends_cleanly:
                issues_found.append(f"Chunk {i}: Final truncado ou incompleto")
                
            # Verificar pares para Tenable WAS
            if pattern_info['has_pairs']:
                pair_status = self._analyze_tenable_pairs(chunk.page_content)
                print(f"👥 Análise de pares: {pair_status}")
                
            print(f"{'─'*50}\n")
        
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
            
        # Primeira linha não-vazia deve ser um marcador OU estar próxima de um
        for line in lines[:5]:  # Verifica primeiras 5 linhas
            if re.search(pattern_info['marker_pattern'], line):
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
        base_vulns = re.findall(r'^VULNERABILITY.*?PLUGIN ID \d+', text, re.MULTILINE)
        instances_vulns = re.findall(r'Instances \(\d+\)', text)
        
        if not base_vulns:
            return "Nenhuma vulnerabilidade BASE encontrada"
        if not instances_vulns:
            return f"{len(base_vulns)} BASE, 0 INSTANCES (possível problema)"
            
        return f"{len(base_vulns)} BASE, {len(instances_vulns)} INSTANCES"
    
    def suggest_improvements(self, issues: list, text: str, pattern_info: dict):
        """Sugere melhorias baseado nos problemas encontrados"""
        print(f"\n{'='*70}")
        print("💡 SUGESTÕES DE MELHORIAS")
        print(f"{'='*70}")
        
        if not issues:
            print("🎉 Nenhum problema crítico encontrado!")
            print("✅ Sistema de chunking está funcionando adequadamente")
            return
            
        print(f"⚠️  Problemas identificados: {len(issues)}\n")
        
        # Categorizar problemas
        size_issues = [i for i in issues if "tokens >" in i]
        structure_issues = [i for i in issues if "truncado" in i or "incompleto" in i]
        
        if size_issues:
            print("📏 PROBLEMAS DE TAMANHO:")
            for issue in size_issues:
                print(f"   • {issue}")
            print("\n💡 Sugestões:")
            print(f"   • Reduzir chunk_size em text_splitter.py")
            print(f"   • Atual: usar {self.max_tokens-1500} tokens máximo por chunk")
            print(f"   • Considerando overhead de prompt (~500) + resposta (~1000)")
            
        if structure_issues:
            print(f"\n🏗️  PROBLEMAS DE ESTRUTURA:")
            for issue in structure_issues:
                print(f"   • {issue}")
            print("\n💡 Sugestões:")
            print("   • Melhorar lógica de divisão em split_text_to_subchunks")
            print("   • Garantir que chunks comecem/terminem em marcadores apropriados")
            if pattern_info['has_pairs']:
                print("   • Para Tenable: preservar pares BASE+INSTANCES completos")
    
    def test_alternative_chunking(self, text: str, pattern_info: dict):
        """Testa estratégia alternativa de chunking"""
        print(f"\n{'='*70}")
        print("🧪 TESTE DE ESTRATÉGIA ALTERNATIVA")
        print(f"{'='*70}")
        
        # Calcular tamanho ideal baseado em tokens
        max_content_tokens = self.max_tokens - 1500
        chars_per_token = len(text) / len(self.tokenizer.encode(text))
        target_chars = int(max_content_tokens * chars_per_token * 0.9)  # 90% de segurança
        
        print(f"📊 Análise de proporção:")
        print(f"   • Total caracteres: {len(text):,}")
        print(f"   • Total tokens: ~{len(self.tokenizer.encode(text)):,}")
        print(f"   • Chars/token: ~{chars_per_token:.1f}")
        print(f"   • Target chars por chunk: ~{target_chars:,}")
        
        # Testar nova divisão
        alternative_chunks = split_text_to_subchunks(text, target_chars)
        
        print(f"\n🔄 Chunks alternativos gerados: {len(alternative_chunks)}")
        
        # Analisar qualidade dos chunks alternativos
        print("\n📝 ANÁLISE DOS CHUNKS ALTERNATIVOS:\n")
        
        for i, chunk_text in enumerate(alternative_chunks[:3], 1):  # Só primeiros 3 para não poluir
            token_count = len(self.tokenizer.encode(chunk_text))
            markers = self._count_vulnerability_markers(chunk_text, pattern_info)
            
            print(f"🧩 Chunk alternativo {i}: {len(chunk_text):,} chars, ~{token_count:,} tokens, {markers} vulns")
            
            if token_count > max_content_tokens:
                print("   ⚠️  Ainda muito grande")
            else:
                print("   ✅ Tamanho adequado")
        
        if len(alternative_chunks) > 3:
            print(f"   ... e mais {len(alternative_chunks)-3} chunks")
    
    def run_complete_analysis(self):
        """Executa análise completa"""
        print("🚀 Iniciando análise completa de chunks...\n")
        
        # 1. Carregar documento
        result = self.load_and_analyze_document()
        if not result:
            return
        text, pattern_info = result
        
        # 2. Analisar chunks atuais
        issues = self.analyze_chunks(text, pattern_info)
        
        # 3. Sugerir melhorias
        self.suggest_improvements(issues, text, pattern_info)
        
        # 4. Testar alternativa
        self.test_alternative_chunking(text, pattern_info)
        
        print(f"\n{'='*70}")
        print("🏁 ANÁLISE COMPLETA FINALIZADA")
        print(f"{'='*70}")
        
        if not issues:
            print("✅ Sistema de chunking está funcionando corretamente!")
        else:
            print(f"⚠️  Encontrados {len(issues)} problemas que podem afetar qualidade")
            print("💡 Revise as sugestões acima para otimizar o sistema")


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