"""
Conversor para formato CSV
"""

import csv
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from .base_converter import BaseConverter


class CSVConverter(BaseConverter):
    """
    Conversor para formato CSV
    """
    
    def __init__(self, delimiter: str = ',', encoding: str = 'utf-8-sig', include_metadata: bool = False):
        """
        Inicializa o conversor CSV
        
        Args:
            delimiter: Delimitador para CSV (padrão: vírgula)
            encoding: Codificação do arquivo (padrão: utf-8-sig para Excel)
            include_metadata: Se True, inclui metadados no mesmo arquivo (padrão: False)
        """
        super().__init__()
        self.delimiter = delimiter
        self.encoding = encoding
        self.include_metadata = include_metadata
    
    def get_format_name(self) -> str:
        return "CSV"
    
    def prepare_data_for_csv(self, data: List[Dict[str, Any]]) -> tuple[List[str], List[List[str]]]:
        """
        Prepara dados para escrita em CSV
        
        Args:
            data: Lista de vulnerabilidades
            
        Returns:
            Tupla com (headers, rows)
        """
        if not data:
            return ['name', 'description'], [['No vulnerabilities found', 'Empty report']]
        
        # Coletar todos os campos únicos
        all_fields = set()
        for item in data:
            all_fields.update(item.keys())
        
        # Ordenar campos com prioridade para campos conhecidos
        headers = []
        for field in self.supported_fields:
            if field in all_fields:
                headers.append(field)
                all_fields.remove(field)
        
        # Adicionar campos restantes em ordem alfabética
        headers.extend(sorted(all_fields))
        
        # Preparar linhas de dados
        rows = []
        for item in data:
            row = []
            for header in headers:
                value = item.get(header, '')
                normalized_value = self.normalize_field_value(value)
                # Escapar aspas duplas no CSV
                if '"' in normalized_value:
                    normalized_value = normalized_value.replace('"', '""')
                row.append(normalized_value)
            rows.append(row)
        
        return headers, rows
    
    def write_metadata_to_csv(self, writer, data: List[Dict[str, Any]]):
        """
        Escreve metadados no mesmo arquivo CSV
        
        Args:
            writer: Objeto csv.writer
            data: Lista de vulnerabilidades
        """
        try:
            # Separação visual
            writer.writerow([])
            writer.writerow(['=== METADADOS ==='])
            writer.writerow([])
            
            writer.writerow(['Propriedade', 'Valor'])
            writer.writerow(['Data de geração', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(['Total de vulnerabilidades', len(data)])
            writer.writerow(['Conversor', f"{self.get_format_name()} Converter"])
            
            # Contar por severidade (usando campo 'Risk' do nosso formato)
            if data:
                severity_counts = {}
                for item in data:
                    severity = item.get('Risk', item.get('severity', 'Unknown'))  # Fallback para compatibilidade
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                writer.writerow([])
                writer.writerow(['Distribuição por Severidade', ''])
                
                for severity, count in severity_counts.items():
                    writer.writerow([f"Severidade {severity}", count])
        
        except Exception as e:
            print(f"Aviso: Erro ao escrever metadados no CSV: {e}")

    def create_metadata_csv(self, data: List[Dict[str, Any]], output_dir: str, base_name: str) -> str:
        """
        Cria arquivo CSV com metadados
        
        Args:
            data: Lista de vulnerabilidades
            output_dir: Diretório de saída
            base_name: Nome base do arquivo
            
        Returns:
            Caminho do arquivo de metadados
        """
        metadata_file = os.path.join(output_dir, f"{base_name}_metadata.csv")
        
        try:
            with open(metadata_file, 'w', newline='', encoding=self.encoding) as f:
                writer = csv.writer(f, delimiter=self.delimiter)
                
                writer.writerow(['Property', 'Value'])
                writer.writerow(['Generated on', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow(['Total vulnerabilities', len(data)])
                writer.writerow(['Converter', f"{self.get_format_name()} Converter"])
                
                # Contar por severidade (usando campo 'Risk' do nosso formato)
                if data:
                    severity_counts = {}
                    for item in data:
                        severity = item.get('Risk', item.get('severity', 'Unknown'))  # Fallback para compatibilidade
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    writer.writerow([])  # Linha vazia
                    writer.writerow(['Severity Distribution', ''])
                    
                    for severity, count in severity_counts.items():
                        writer.writerow([f"Severity {severity}", count])
            
            return metadata_file
        except Exception as e:
            print(f"Aviso: Não foi possível criar arquivo de metadados: {e}")
            return ""
    
    def convert(self, json_file_path: str, output_file_path: Optional[str] = None) -> str:
        """
        Converte arquivo JSON para CSV
        
        Args:
            json_file_path: Caminho para o arquivo JSON
            output_file_path: Caminho opcional para o arquivo de saída
            
        Returns:
            Caminho do arquivo CSV gerado
        """
        # Carregar dados
        data = self.load_json_data(json_file_path)
        
        if not self.validate_data(data):
            raise ValueError("Dados JSON inválidos")
        
        # Definir arquivo de saída
        if output_file_path is None:
            output_file_path = self.get_output_filename(json_file_path, "csv")
        
        try:
            # Preparar dados
            headers, rows = self.prepare_data_for_csv(data)
            
            # Escrever arquivo CSV
            with open(output_file_path, 'w', newline='', encoding=self.encoding) as f:
                writer = csv.writer(f, delimiter=self.delimiter)
                
                # Escrever cabeçalho
                writer.writerow(headers)
                
                # Escrever dados
                writer.writerows(rows)
                
                # Incluir metadados no mesmo arquivo se solicitado
                if self.include_metadata:
                    self.write_metadata_to_csv(writer, data)
            
            # Criar arquivo de metadados separado apenas se include_metadata for False
            metadata_file = None
            if not self.include_metadata:
                output_dir = os.path.dirname(output_file_path) or '.'
                base_name = os.path.splitext(os.path.basename(output_file_path))[0]
                metadata_file = self.create_metadata_csv(data, output_dir, base_name)
            
            print(f"Arquivo CSV criado com sucesso: {output_file_path}")
            print(f"Total de vulnerabilidades: {len(data)}")
            if metadata_file:
                print(f"Metadados salvos em: {metadata_file}")
            elif self.include_metadata:
                print("Metadados incluídos no arquivo CSV principal")
            
            return output_file_path
            
        except Exception as e:
            raise Exception(f"Erro ao criar arquivo CSV: {e}")


class TSVConverter(CSVConverter):
    """
    Conversor para formato TSV (Tab-Separated Values)
    """
    
    def __init__(self, encoding: str = 'utf-8-sig', include_metadata: bool = False):
        super().__init__(delimiter='\t', encoding=encoding, include_metadata=include_metadata)
    
    def get_format_name(self) -> str:
        return "TSV"


def convert_json_to_csv(json_file_path: str, output_file_path: Optional[str] = None, 
                       delimiter: str = ',', encoding: str = 'utf-8-sig') -> str:
    """
    Função utilitária para conversão direta para CSV
    
    Args:
        json_file_path: Caminho para o arquivo JSON
        output_file_path: Caminho opcional para o arquivo de saída
        delimiter: Delimitador CSV
        encoding: Codificação do arquivo
        
    Returns:
        Caminho do arquivo CSV gerado
    """
    converter = CSVConverter(delimiter=delimiter, encoding=encoding)
    return converter.convert(json_file_path, output_file_path)


def convert_json_to_tsv(json_file_path: str, output_file_path: Optional[str] = None) -> str:
    """
    Função utilitária para conversão direta para TSV
    
    Args:
        json_file_path: Caminho para o arquivo JSON
        output_file_path: Caminho opcional para o arquivo de saída
        
    Returns:
        Caminho do arquivo TSV gerado
    """
    converter = TSVConverter()
    return converter.convert(json_file_path, output_file_path)