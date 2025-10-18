"""
Classe base abstrata para conversores de formato
Define a interface comum para todos os conversores
"""

from abc import ABC, abstractmethod
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime


class BaseConverter(ABC):
    """
    Classe base abstrata para conversores de formato
    """
    
    def __init__(self):
        # Campos do nosso formato JSON atual
        self.supported_fields = [
            'Name',
            'name',
            'Synopsis', 
            'Description',
            'Plugin Output',
            'Solution',
            'See Also',
            'CVSSv3',
            'CVSSv4',
            'Risk'
        ]
    
    def load_json_data(self, json_file_path: str) -> List[Dict[str, Any]]:
        """
        Carrega dados JSON de um arquivo
        
        Args:
            json_file_path: Caminho para o arquivo JSON
            
        Returns:
            Lista de dicionários com os dados das vulnerabilidades
        """
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                raise ValueError("JSON deve conter uma lista de vulnerabilidades")
            
            return data
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo JSON não encontrado: {json_file_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Erro ao decodificar JSON: {e}")
    
    def validate_data(self, data: List[Dict[str, Any]]) -> bool:
        """
        Valida se os dados estão no formato esperado
        
        Args:
            data: Lista de dicionários com dados das vulnerabilidades
            
        Returns:
            True se os dados são válidos
        """
        if not isinstance(data, list):
            return False
        
        for item in data:
            if not isinstance(item, dict):
                return False
            
            # Verificar se tem pelo menos o campo 'name' (minúsculo) ou 'Name' (maiúsculo)
            if 'name' not in item and 'Name' not in item:
                return False
        
        return True
    
    def get_output_filename(self, input_filename: str, extension: str) -> str:
        """
        Gera nome do arquivo de saída baseado no arquivo de entrada
        
        Args:
            input_filename: Nome do arquivo de entrada
            extension: Extensão do arquivo de saída (sem ponto)
            
        Returns:
            Nome do arquivo de saída
        """
        base_name = os.path.splitext(os.path.basename(input_filename))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{base_name}_converted_{timestamp}.{extension}"
    
    def normalize_field_value(self, value: Any) -> str:
        """
        Normaliza valores de campos para string
        
        Args:
            value: Valor a ser normalizado
            
        Returns:
            String normalizada
        """
        if value is None:
            return ""
        if isinstance(value, (list, dict)):
            return str(value)
        return str(value).strip()
    
    @abstractmethod
    def convert(self, json_file_path: str, output_file_path: Optional[str] = None) -> str:
        """
        Converte arquivo JSON para o formato específico
        
        Args:
            json_file_path: Caminho para o arquivo JSON de entrada
            output_file_path: Caminho opcional para o arquivo de saída
            
        Returns:
            Caminho do arquivo gerado
        """
        pass
    
    @abstractmethod
    def get_format_name(self) -> str:
        """
        Retorna o nome do formato
        
        Returns:
            Nome do formato (ex: "XLSX", "CSV")
        """
        pass