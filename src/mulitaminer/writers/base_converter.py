"""
Classe base abstrata para conversores de formato
Define a interface comum para todos os conversores
"""

from abc import ABC, abstractmethod
import json
import os
from typing import List, Dict, Any, Callable, Optional

from ..configs.vuln_schema import validation_types


# format name -> factory(args) -> converter instance. Each converter file
# registers its own factory (co-locating per-format construction), the same
# Open/Closed pattern the input readers and LLM providers use. This is also the
# seam the standard-format exporters (SARIF/CSAF, see OUTPUT_STANDARDS.md) plug
# into later — a new format is a new file + one decorator, no dispatch edit.
ConverterFactory = Callable[[Any], "BaseConverter"]
_CONVERTER_FACTORIES: dict[str, ConverterFactory] = {}


def register_converter(*names: str) -> Callable[[ConverterFactory], ConverterFactory]:
    """Decorator: register a converter factory under one or more format names."""
    def deco(factory: ConverterFactory) -> ConverterFactory:
        for name in names:
            _CONVERTER_FACTORIES[name.lower()] = factory
        return factory
    return deco


def get_converter_factory(name: str) -> Optional[ConverterFactory]:
    """Return the registered factory for a format name, or None."""
    return _CONVERTER_FACTORIES.get(name.lower())


def available_formats() -> list[str]:
    """Registered output format names — drives the ``--convert all`` expansion."""
    return sorted(_CONVERTER_FACTORIES)


class BaseConverter(ABC):
    """
    Classe base abstrata para conversores de formato
    """

    def __init__(self):
        # Column ordering priority: the record contract's fields in declaration
        # order, derived from the single-source schema so it can never drift.
        self.supported_fields = list(validation_types())
    
    def load_json_data(self, json_file_path: str) -> List[Dict[str, Any]]:
        """
        Load JSON data from file
        
        Args:
            json_file_path: Path to JSON file
            
        Returns:
            List of dictionaries with vulnerability data
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
        Validate if data is in expected format
        
        Args:
            data: List of dictionaries with vulnerability data
            
        Returns:
            True if data is valid
        """
        if not isinstance(data, list):
            return False
        
        for item in data:
            if not isinstance(item, dict):
                return False
            
            # Check if has at least 'name' field (lowercase) or 'Name' (uppercase)
            if 'name' not in item and 'Name' not in item:
                return False
        
        return True
    
    def get_output_filename(self, input_filename: str, extension: str) -> str:
        """
        Generate output filename based on input file
        
        Args:
            input_filename: Input filename
            extension: Output file extension (without dot)
            
        Returns:
            Output filename (same directory, same name, different extension)
        """
        input_dir = os.path.dirname(input_filename)
        base_name = os.path.splitext(os.path.basename(input_filename))[0]
        output_filename = f"{base_name}.{extension}"
        return os.path.join(input_dir, output_filename) if input_dir else output_filename
    
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