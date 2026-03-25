"""
Orchestrator for format conversions (CSV, TSV, XLSX).
Manages the conversion workflow based on command-line arguments.
"""

import os
from typing import List, Optional
from .xlsx_converter import XLSXConverter
from .csv_converter import CSVConverter, TSVConverter


def convert_single_format(json_file_path: str, format_type: str, args) -> Optional[str]:
    """
    Converts to a specific format.
    The converted file name follows the original JSON naming pattern (including model and timestamp).
    
    Args:
        json_file_path: Path to the JSON file to convert
        format_type: Format to convert to ('csv', 'xlsx', or 'tsv')
        args: Parsed command-line arguments
        
    Returns:
        Path to the converted file, or None if conversion failed
    """
    try:
        base_name = os.path.splitext(os.path.basename(json_file_path))[0]
        
        # Generate output filename with correct extension
        # Keeps the JSON base name (which already includes model and timestamp)
        if hasattr(args, 'output_file') and args.output_file and args.convert != 'all':
            # If xlsx, force .xlsx extension
            if format_type == 'xlsx':
                output_file = os.path.splitext(args.output_file)[0] + '.xlsx'
            elif format_type == 'csv':
                output_file = os.path.splitext(args.output_file)[0] + '.csv'
            elif format_type == 'tsv':
                output_file = os.path.splitext(args.output_file)[0] + '.tsv'
            else:
                output_file = args.output_file
        else:
            if hasattr(args, 'output_dir') and args.output_dir:
                output_file = os.path.join(args.output_dir, f"{base_name}.{format_type}")
            else:
                # Uses the same base name as the JSON (already has model + timestamp)
                output_file = f"{base_name}.{format_type}"
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Select appropriate converter
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
        
        # Convert
        result = converter.convert(json_file_path, output_file)
        print(f"✅ {format_type.upper()}: {result}")
        return result
        
    except Exception as e:
        print(f"❌ Error converting to {format_type.upper()}: {e}")
        return None


def execute_conversions(json_file_path: str, args) -> List[str]:
    """
    Executes conversions based on provided arguments.
    
    Args:
        json_file_path: Path to the JSON file to convert
        args: Parsed command-line arguments containing:
            - args.convert: 'csv', 'tsv', 'xlsx', 'all', or 'none'
            - args.output_dir: Optional output directory
            - args.output_file: Optional output filename
            - args.csv_delimiter: CSV delimiter (default: ',')
            - args.csv_encoding: CSV encoding (default: 'utf-8-sig')
    
    Returns:
        List of paths to converted files
    """
    convert_type = getattr(args, 'convert', 'none')
    
    if convert_type == 'none':
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
