"""CSV/TSV converters."""

import csv
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from .base_converter import BaseConverter


class CSVConverter(BaseConverter):
    """Converts extraction JSON to CSV."""

    def __init__(self, delimiter: str = ',', encoding: str = 'utf-8-sig', include_metadata: bool = False):
        super().__init__()
        self.delimiter = delimiter
        self.encoding = encoding
        self.include_metadata = include_metadata

    def get_format_name(self) -> str:
        return "CSV"

    def prepare_data_for_csv(self, data: List[Dict[str, Any]]) -> tuple[List[str], List[List[str]]]:
        """Build headers (known fields first) and normalized rows."""
        if not data:
            return ['name', 'description'], [['No vulnerabilities found', 'Empty report']]

        all_fields = set()
        for item in data:
            all_fields.update(item.keys())

        headers = []
        for field in self.supported_fields:
            if field in all_fields:
                headers.append(field)
                all_fields.remove(field)

        headers.extend(sorted(all_fields))

        rows = []
        for item in data:
            row = []
            for header in headers:
                value = item.get(header, '')
                normalized_value = self.normalize_field_value(value)
                if '"' in normalized_value:
                    normalized_value = normalized_value.replace('"', '""')
                row.append(normalized_value)
            rows.append(row)

        return headers, rows

    def write_metadata_to_csv(self, writer, data: List[Dict[str, Any]]):
        """Append a metadata section to the same CSV file."""
        try:
            writer.writerow([])
            writer.writerow(['=== METADADOS ==='])
            writer.writerow([])

            writer.writerow(['Propriedade', 'Valor'])
            writer.writerow(['Generated date', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(['Total vulnerabilities', len(data)])
            writer.writerow(['Conversor', f"{self.get_format_name()} Converter"])

            if data:
                severity_counts = {}
                for item in data:
                    severity = item.get('Risk', item.get('severity', 'Unknown'))
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                writer.writerow([])
                writer.writerow(['Severity Distribution', ''])

                for severity, count in severity_counts.items():
                    writer.writerow([f"Severity {severity}", count])

        except Exception as e:
            print(f"Warning: Error writing metadata to CSV: {e}")

    def create_metadata_csv(self, data: List[Dict[str, Any]], output_dir: str, base_name: str) -> str:
        """Write a standalone metadata CSV; returns its path ('' on failure)."""
        metadata_file = os.path.join(output_dir, f"{base_name}_metadata.csv")

        try:
            with open(metadata_file, 'w', newline='', encoding=self.encoding) as f:
                writer = csv.writer(f, delimiter=self.delimiter)

                writer.writerow(['Property', 'Value'])
                writer.writerow(['Generated on', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow(['Total vulnerabilities', len(data)])
                writer.writerow(['Converter', f"{self.get_format_name()} Converter"])

                if data:
                    severity_counts = {}
                    for item in data:
                        severity = item.get('Risk', item.get('severity', 'Unknown'))
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    writer.writerow([])
                    writer.writerow(['Severity Distribution', ''])

                    for severity, count in severity_counts.items():
                        writer.writerow([f"Severity {severity}", count])

            return metadata_file
        except Exception as e:
            print(f"Warning: Could not create metadata file: {e}")
            return ""

    def convert(self, json_file_path: str, output_file_path: Optional[str] = None) -> str:
        """Convert a JSON file to CSV and return the output path."""
        data = self.load_json_data(json_file_path)

        if not self.validate_data(data):
            raise ValueError("Invalid JSON data")

        if output_file_path is None:
            output_file_path = self.get_output_filename(json_file_path, "csv")

        try:
            headers, rows = self.prepare_data_for_csv(data)

            with open(output_file_path, 'w', newline='', encoding=self.encoding) as f:
                writer = csv.writer(f, delimiter=self.delimiter)
                writer.writerow(headers)
                writer.writerows(rows)

                if self.include_metadata:
                    self.write_metadata_to_csv(writer, data)

            # Separate metadata file only when it was not embedded above
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
    """Converts extraction JSON to TSV."""

    def __init__(self, encoding: str = 'utf-8-sig', include_metadata: bool = False):
        super().__init__(delimiter='\t', encoding=encoding, include_metadata=include_metadata)

    def get_format_name(self) -> str:
        return "TSV"


def convert_json_to_csv(json_file_path: str, output_file_path: Optional[str] = None,
                       delimiter: str = ',', encoding: str = 'utf-8-sig') -> str:
    """Direct JSON to CSV conversion helper."""
    converter = CSVConverter(delimiter=delimiter, encoding=encoding)
    return converter.convert(json_file_path, output_file_path)


def convert_json_to_tsv(json_file_path: str, output_file_path: Optional[str] = None) -> str:
    """Direct JSON to TSV conversion helper."""
    converter = TSVConverter()
    return converter.convert(json_file_path, output_file_path)
