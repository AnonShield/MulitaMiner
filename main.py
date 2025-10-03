#!/usr/bin/env python3
"""
PDF Vulnerability Extractor - Main Application

A professional tool for extracting security vulnerabilities from PDF reports
using OpenAI GPT models and LangChain framework with FAISS vector storage.

Author: Security Team
Version: 2.0.0
License: MIT
"""

import sys
import argparse
import logging
from pathlib import Path

# Import our modular components
from src.config import ConfigManager, setup_logging
from src.pdf_processor import PDFProcessor
from src.vulnerability_extractor import VulnerabilityExtractor
from src.utils import ResultProcessor, FileValidator
from src.data_converter import DataConverter


class PDFVulnerabilityExtractorApp:
    """Main application class that orchestrates the vulnerability extraction process."""
    
    def __init__(self, config_path: str = "config.json"):
        """Initialize the application.
        
        Args:
            config_path: Path to configuration file
        """
        # Setup logging first
        setup_logging()
        
        # Initialize components
        self.config_manager = ConfigManager(config_path)
        self.pdf_processor = PDFProcessor(
            chunk_size=200,
            chunk_overlap=50
        )
        self.vulnerability_extractor = VulnerabilityExtractor(
            model_name=self.config_manager.get_model_name(),
            max_tokens=800
        )
        
        # Initialize data converter
        self.data_converter = DataConverter()
        
        logging.info("PDF Vulnerability Extractor initialized successfully")
    
    def process_pdf(self, pdf_path: str, output_dir: str, save_csv: bool = False, 
                   save_excel: bool = False, save_all: bool = False) -> str:
        """Main processing pipeline for PDF vulnerability extraction.
        
        Args:
            pdf_path: Path to PDF file
            output_dir: Output directory
            save_csv: Save results in CSV format
            save_excel: Save results in Excel format  
            save_all: Save results in all formats
            
        Returns:
            Path to final results file
        """
        try:
            # Ensure output directory exists
            ResultProcessor.ensure_output_directory(output_dir)
            
            # Process PDF
            logging.info(f"Starting processing of PDF: {pdf_path}")
            texts = self.pdf_processor.load_and_process_pdf(pdf_path)
            
            # Create vector store and QA chain
            vector_store = self.pdf_processor.create_vector_store(texts)
            qa_chain = self.vulnerability_extractor.setup_qa_chain(
                vector_store, 
                retrieval_k=5
            )
            
            # Extract vulnerabilities incrementally
            jsonl_path = self.vulnerability_extractor.extract_vulnerabilities_incremental(
                texts, 
                output_dir
            )
            
            # Perform final comprehensive search
            self.vulnerability_extractor.perform_final_search(qa_chain, jsonl_path)
            
            # Consolidate results
            final_path = ResultProcessor.consolidate_results(jsonl_path, output_dir)
            
            # Load and display statistics
            with open(final_path, "r", encoding="utf-8") as f:
                import json
                vulnerabilities = json.load(f)
            
            ResultProcessor.log_statistics(vulnerabilities)
            
            # Save in additional formats if requested
            if save_all or save_csv or save_excel:
                logging.info("Saving results in additional formats...")
                
                if save_all or save_csv:
                    try:
                        csv_path = self.data_converter.json_to_csv(final_path)
                        logging.info(f"CSV file saved: {csv_path}")
                    except Exception as e:
                        logging.error(f"Error saving CSV: {e}")
                
                if save_all or save_excel:
                    try:
                        excel_path = self.data_converter.json_to_excel(final_path)
                        logging.info(f"Excel file saved: {excel_path}")
                    except Exception as e:
                        logging.error(f"Error saving Excel: {e}")
            
            logging.info(f"Processing completed successfully!")
            logging.info(f"Results saved to: {final_path}")
            
            return final_path
            
        except Exception as e:
            logging.error(f"Error during processing: {e}")
            raise


def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup command line argument parser.
    
    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Professional PDF Vulnerability Extractor using OpenAI GPT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --pdf "security_report.pdf"
  python main.py --pdf "/path/to/report.pdf" --output "./results"
  python main.py --pdf "report.pdf" --save-csv
  python main.py --pdf "report.pdf" --save-excel
  python main.py --pdf "report.pdf" --save-all
        """
    )
    
    parser.add_argument(
        "--pdf", 
        type=str, 
        default="./WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf",
        help="Path to PDF file to process (default: ./WAS_Web_app_scan_Juice_Shop___bWAAP-2[1].pdf)"
    )
    
    parser.add_argument(
        "--output", 
        type=str, 
        default="./output",
        help="Output directory for results (default: ./output)"
    )
    
    # Export format options
    parser.add_argument(
        "--save-csv",
        action="store_true",
        help="Save results in CSV format alongside JSON"
    )
    
    parser.add_argument(
        "--save-excel",
        action="store_true",
        help="Save results in Excel format alongside JSON"
    )
    
    parser.add_argument(
        "--save-all",
        action="store_true", 
        help="Save results in all formats (JSON, CSV, Excel)"
    )
    
    return parser


def main() -> None:
    """Main entry point."""
    try:
        # Parse arguments
        parser = setup_argument_parser()
        args = parser.parse_args()
        
        # Initialize application
        app = PDFVulnerabilityExtractorApp()
        
        # Validate PDF file exists
        if not FileValidator.validate_file_exists(args.pdf, "PDF file"):
            sys.exit(1)
        
        # Validate PDF extension
        if not FileValidator.ensure_file_extension(args.pdf, ".pdf"):
            logging.warning(f"File '{args.pdf}' does not have .pdf extension")
        
        # Process PDF with format options
        final_path = app.process_pdf(
            args.pdf, 
            args.output,
            save_csv=args.save_csv,
            save_excel=args.save_excel,
            save_all=args.save_all
        )
        
        logging.info("Application completed successfully!")
        
    except KeyboardInterrupt:
        logging.info("Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()