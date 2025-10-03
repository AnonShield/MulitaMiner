#!/usr/bin/env python3
"""
Data Conversion Example Script

This script demonstrates how to use the data conversion capabilities
of the PDF Vulnerability Extractor.
"""

import os
import sys
from pathlib import Path

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.data_converter import DataConverter


def main():
    """Demonstrate data conversion capabilities."""
    
    print("PDF Vulnerability Extractor - Data Conversion Example")
    print("=" * 60)
    
    # Initialize converter
    converter = DataConverter()
    
    # Path to JSON file
    json_file = "output/vulnerabilities_extracted.json"
    
    if not os.path.exists(json_file):
        print(f"Error: JSON file not found: {json_file}")
        print("Please run the main extraction first:")
        print("  python main.py --pdf your_report.pdf")
        return
    
    try:
        print(f"Processing file: {json_file}")
        print()
        
        # 1. Convert to CSV
        print("1. Converting to CSV format...")
        csv_file = converter.json_to_csv(json_file)
        print(f"   CSV file created: {csv_file}")
        print()
        
        # 2. Convert to Excel
        print("2. Converting to Excel format...")
        excel_file = converter.json_to_excel(json_file)
        print(f"   Excel file created: {excel_file}")
        print()
        
        # 3. Display file sizes
        print("4. File size comparison:")
        json_size = os.path.getsize(json_file) / 1024
        csv_size = os.path.getsize(csv_file) / 1024
        excel_size = os.path.getsize(excel_file) / 1024
        
        print(f"   JSON:  {json_size:.1f} KB")
        print(f"   CSV:   {csv_size:.1f} KB")
        print(f"   Excel: {excel_size:.1f} KB")
        print()
        
        # 4. Usage examples
        print("4. Usage examples via command line:")
        print("   # Save PDF results directly to CSV:")
        print("   python main.py --pdf \"scan.pdf\" --save-csv")
        print()
        print("   # Save to Excel format:")
        print("   python main.py --pdf \"scan.pdf\" --save-excel")
        print()
        print("   # Save to all formats:")
        print("   python main.py --pdf \"scan.pdf\" --save-all")
        print()
        
        print("Conversion examples completed successfully!")
        
    except Exception as e:
        print(f"Error during conversion: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())