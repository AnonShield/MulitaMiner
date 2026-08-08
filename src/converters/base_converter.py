"""Abstract base class for output format converters."""

from abc import ABC, abstractmethod
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime


class BaseConverter(ABC):
    """Common interface for all format converters."""

    def __init__(self):
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
        """Load a list of vulnerability dicts from a JSON file."""
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
        """Check that data is a list of dicts with a 'name'/'Name' field."""
        if not isinstance(data, list):
            return False

        for item in data:
            if not isinstance(item, dict):
                return False

            if 'name' not in item and 'Name' not in item:
                return False

        return True

    def get_output_filename(self, input_filename: str, extension: str) -> str:
        """Same directory and base name as the input, with a new extension."""
        input_dir = os.path.dirname(input_filename)
        base_name = os.path.splitext(os.path.basename(input_filename))[0]
        output_filename = f"{base_name}.{extension}"
        return os.path.join(input_dir, output_filename) if input_dir else output_filename

    def normalize_field_value(self, value: Any) -> str:
        """Normalize a field value to a plain string."""
        if value is None:
            return ""
        if isinstance(value, (list, dict)):
            return str(value)
        return str(value).strip()

    @abstractmethod
    def convert(self, json_file_path: str, output_file_path: Optional[str] = None) -> str:
        """Convert the JSON file and return the generated file path."""
        pass

    @abstractmethod
    def get_format_name(self) -> str:
        """Return the format name (e.g. "XLSX", "CSV")."""
        pass
