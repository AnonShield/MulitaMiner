"""Orchestrator for format conversions (CSV, TSV, XLSX)."""

import os
from typing import List, Optional
from .xlsx_converter import XLSXConverter
from .csv_converter import CSVConverter, TSVConverter


def convert_single_format(json_file_path: str, format_type: str, args) -> Optional[str]:
    """Convert to one format; returns the output path or None on failure."""
    try:
        base_name = os.path.splitext(os.path.basename(json_file_path))[0]

        # Output keeps the JSON base name (already includes model and timestamp)
        if hasattr(args, 'output_file') and args.output_file and args.convert != 'all':
            ext = {'xlsx': '.xlsx', 'csv': '.csv', 'tsv': '.tsv'}.get(format_type, '')
            # Only strip a recognized format extension; otherwise keep the name as-is
            # (avoids splitext eating dotted suffixes like "...5.11.0_gpt4_run1").
            root, current_ext = os.path.splitext(args.output_file)
            base = root if current_ext.lower() in {'.xlsx', '.csv', '.tsv', '.json'} else args.output_file
            output_file = base + ext
            # Honor --output-dir when output_file is a bare name
            if (getattr(args, 'output_dir', None)
                    and not os.path.isabs(output_file)
                    and not os.path.dirname(output_file)):
                output_file = os.path.join(args.output_dir, output_file)
        else:
            if hasattr(args, 'output_dir') and args.output_dir:
                output_file = os.path.join(args.output_dir, f"{base_name}.{format_type}")
            else:
                json_dir = os.path.dirname(json_file_path)
                if json_dir:
                    output_file = os.path.join(json_dir, f"{base_name}.{format_type}")
                else:
                    output_file = f"{base_name}.{format_type}"
        
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        if format_type == 'csv':
            csv_delimiter = getattr(args, 'csv_delimiter', ',')
            csv_encoding = getattr(args, 'csv_encoding', 'utf-8-sig')
            converter = CSVConverter(
                delimiter=csv_delimiter,
                encoding=csv_encoding,
                include_metadata=False
            )
        elif format_type == 'tsv':
            csv_encoding = getattr(args, 'csv_encoding', 'utf-8-sig')
            converter = TSVConverter(encoding=csv_encoding, include_metadata=False)
        elif format_type == 'xlsx':
            converter = XLSXConverter()
        else:
            raise ValueError(f"Unsupported format: {format_type}")

        result = converter.convert(json_file_path, output_file)
        print(f"✅ {format_type.upper()}: {result}")
        return result
        
    except Exception as e:
        print(f"❌ Error converting to {format_type.upper()}: {e}")
        return None


def execute_conversions(json_file_path: str, args) -> List[str]:
    """Run the conversions requested by args.convert; returns output paths."""
    convert_type = getattr(args, 'convert', None)

    if not convert_type:
        return []
    
    print(f"\n=== FORMAT CONVERSIONS ===")
    converted_files = []
    
    if convert_type == 'all':
        formats = ['csv', 'tsv', 'xlsx']
        for format_type in formats:
            try:
                result = convert_single_format(json_file_path, format_type, args)
                if result:
                    converted_files.append(result)
            except Exception as e:
                print(f"Error converting to {format_type.upper()}: {e}")
    else:
        result = convert_single_format(json_file_path, convert_type, args)
        if result:
            converted_files.append(result)
    
    return converted_files
