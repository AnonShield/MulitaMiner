"""
Data Converter Module

This module provides functionality to convert vulnerability data between different formats.
Supports JSON to CSV and Excel conversion for analysis and reporting purposes.
"""

import json
import csv
import pandas as pd
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class DataConverter:
    """
    Handles conversion of vulnerability data between different formats.
    """
    
    def __init__(self):
        self.supported_formats = ['csv', 'xlsx', 'excel']
    
    def json_to_csv(self, json_file_path: str, csv_file_path: Optional[str] = None) -> str:
        """
        Convert JSON vulnerability data to CSV format.
        
        Args:
            json_file_path: Path to the input JSON file
            csv_file_path: Path for the output CSV file (optional)
            
        Returns:
            Path to the created CSV file
        """
        try:
            # Generate output path if not provided
            if csv_file_path is None:
                json_path = Path(json_file_path)
                csv_file_path = json_path.parent / f"{json_path.stem}.csv"
            
            # Load JSON data
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not data:
                logger.warning("No data found in JSON file")
                return csv_file_path
            
            # Get all possible fieldnames from the data
            fieldnames = set()
            for item in data:
                fieldnames.update(item.keys())
            fieldnames = sorted(list(fieldnames))
            
            # Write CSV file
            with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for item in data:
                    # Ensure all fields are present
                    row = {field: item.get(field, '') for field in fieldnames}
                    writer.writerow(row)
            
            logger.info(f"Successfully converted {len(data)} vulnerabilities to CSV: {csv_file_path}")
            return str(csv_file_path)
            
        except Exception as e:
            logger.error(f"Error converting JSON to CSV: {e}")
            raise
    
    def json_to_excel(self, json_file_path: str, excel_file_path: Optional[str] = None) -> str:
        """
        Convert JSON vulnerability data to Excel format.
        
        Args:
            json_file_path: Path to the input JSON file
            excel_file_path: Path for the output Excel file (optional)
            
        Returns:
            Path to the created Excel file
        """
        try:
            # Generate output path if not provided
            if excel_file_path is None:
                json_path = Path(json_file_path)
                excel_file_path = json_path.parent / f"{json_path.stem}.xlsx"
            
            # Load JSON data
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not data:
                logger.warning("No data found in JSON file")
                return excel_file_path
            
            # Convert to DataFrame
            df = pd.DataFrame(data)
            
            # Create Excel file with formatting
            with pd.ExcelWriter(excel_file_path, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
                
                # Get the workbook and worksheet
                workbook = writer.book
                worksheet = writer.sheets['Vulnerabilities']
                
                # Auto-adjust column widths
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    
                    # Set a reasonable maximum width
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
                
                # Add summary sheet
                self._add_summary_sheet(writer, df)
            
            logger.info(f"Successfully converted {len(data)} vulnerabilities to Excel: {excel_file_path}")
            return str(excel_file_path)
            
        except Exception as e:
            logger.error(f"Error converting JSON to Excel: {e}")
            raise
    
    def _add_summary_sheet(self, writer: pd.ExcelWriter, df: pd.DataFrame):
        """
        Add a summary sheet with vulnerability statistics to the Excel file.
        
        Args:
            writer: Excel writer object
            df: DataFrame containing vulnerability data
        """
        try:
            summary_data = []
            
            # Total vulnerabilities
            summary_data.append(['Total Vulnerabilities', len(df)])
            
            # Severity distribution
            if 'severity' in df.columns:
                severity_counts = df['severity'].value_counts()
                summary_data.append(['', ''])  # Empty row
                summary_data.append(['Severity Distribution', ''])
                for severity, count in severity_counts.items():
                    summary_data.append([f'  {severity}', count])
            
            # Top vulnerabilities by frequency
            if 'name' in df.columns:
                name_counts = df['name'].value_counts().head(10)
                summary_data.append(['', ''])  # Empty row
                summary_data.append(['Top 10 Vulnerabilities', ''])
                for name, count in name_counts.items():
                    summary_data.append([f'  {name}', count])
            
            # Create summary DataFrame
            summary_df = pd.DataFrame(summary_data, columns=['Metric', 'Value'])
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Format summary sheet
            summary_worksheet = writer.sheets['Summary']
            summary_worksheet.column_dimensions['A'].width = 40
            summary_worksheet.column_dimensions['B'].width = 15
            
        except Exception as e:
            logger.warning(f"Could not create summary sheet: {e}")
    
    def convert_data(self, input_file: str, output_format: str, output_file: Optional[str] = None) -> str:
        """
        Convert vulnerability data to the specified format.
        
        Args:
            input_file: Path to the input JSON file
            output_format: Target format ('csv', 'xlsx', 'excel')
            output_file: Path for the output file (optional)
            
        Returns:
            Path to the converted file
        """
        if output_format.lower() not in self.supported_formats:
            raise ValueError(f"Unsupported format: {output_format}. Supported formats: {self.supported_formats}")
        
        if output_format.lower() == 'csv':
            return self.json_to_csv(input_file, output_file)
        elif output_format.lower() in ['xlsx', 'excel']:
            return self.json_to_excel(input_file, output_file)
        else:
            raise ValueError(f"Format {output_format} not implemented")


def main():
    """
    Example usage of the data converter.
    """
    converter = DataConverter()
    
    # Example conversion
    json_file = "output/vulnerabilities_extracted.json"
    
    try:
        # Convert to CSV
        csv_file = converter.json_to_csv(json_file)
        print(f"CSV file created: {csv_file}")
        
        # Convert to Excel
        excel_file = converter.json_to_excel(json_file)
        print(f"Excel file created: {excel_file}")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()