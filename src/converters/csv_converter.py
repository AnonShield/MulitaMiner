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
    CSV Converter
    """
    
    def __init__(self, delimiter: str = ',', encoding: str = 'utf-8-sig', include_metadata: bool = False):
        """
        Initialize CSV converter
        
        Args:
            delimiter: CSV delimiter (default: comma)
            encoding: File encoding (default: utf-8-sig for Excel)
            include_metadata: If True, includes metadata in same file (default: False)
        """
        super().__init__()
        self.delimiter = delimiter
        self.encoding = encoding
        self.include_metadata = include_metadata
    
    def get_format_name(self) -> str:
        return "CSV"
    
    def prepare_data_for_csv(self, data: List[Dict[str, Any]]) -> tuple[List[str], List[List[str]]]:
        """
        Prepare data for csv output, normalizing values and determining headers
        """
        if not data:
            return ['name', 'description'], [['No vulnerabilities found', 'Empty report']]
        
        # Collect all unique fields
        all_fields = set()
        for item in data:
            all_fields.update(item.keys())
        
        # Ordenar campos com prioridade para campos conhecidos
        headers = []
        for field in self.supported_fields:
            if field in all_fields:
                headers.append(field)
                all_fields.remove(field)
        
        # Add remaining fields in alphabetical order
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
        Write metadata to same CSV file
        
        Args:
            writer: csv.writer object
            data: List of vulnerabilities
        """
        try:
            # Visual separation
            writer.writerow([])
            writer.writerow(['=== METADADOS ==='])
            writer.writerow([])
            
            writer.writerow(['Propriedade', 'Valor'])
            writer.writerow(['Generated date', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(['Total vulnerabilities', len(data)])
            writer.writerow(['Conversor', f"{self.get_format_name()} Converter"])
            
            # Contar por severidade (usando campo 'Risk' do nosso formato)
            if data:
                severity_counts = {}
                for item in data:
                    severity = item.get('Risk', item.get('severity', 'Unknown'))  # Fallback para compatibilidade
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                writer.writerow([])
                writer.writerow(['Severity Distribution', ''])
                
                for severity, count in severity_counts.items():
                    writer.writerow([f"Severity {severity}", count])
        
        except Exception as e:
            print(f"Warning: Error writing metadata to CSV: {e}")

    def create_metadata_csv(self, data: List[Dict[str, Any]], output_dir: str, base_name: str) -> str:
        """
        Create CSV file with metadata
        
        Args:
            data: List of vulnerabilities
            output_dir: Output directory
            base_name: Base filename
            
        Returns:
            Path to metadata file
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
            print(f"Warning: Could not create metadata file: {e}")
            return ""
    
    def convert(self, json_file_path: str, output_file_path: Optional[str] = None) -> str:
        """
        Convert JSON file to CSV
        
        Args:
            json_file_path: Path to JSON file
            output_file_path: Optional path to output file
            
        Returns:
            Path of generated CSV file
        """
        # Load data
        data = self.load_json_data(json_file_path)
        
        if not self.validate_data(data):
            raise ValueError("Invalid JSON data")
        
        # Set output file
        if output_file_path is None:
            output_file_path = self.get_output_filename(json_file_path, "csv")
        
        try:
            # Preparar dados
            headers, rows = self.prepare_data_for_csv(data)
            
            # Escrever arquivo CSV
            with open(output_file_path, 'w', newline='', encoding=self.encoding) as f:
                writer = csv.writer(f, delimiter=self.delimiter)
                
                # Write header
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
                print("Metadata included in main CSV file")
            
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