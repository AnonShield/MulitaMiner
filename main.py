import os
import sys
import json
from pdf_extractor_tenablewas import TenableWASPDFExtractor

def main():
    """
    Main function to extract information from TenableWAS PDF reports.
    """
    print("SafeAnon - TenableWAS PDF Extractor")
    print("-" * 50)
    
    # Check if a PDF file was provided as an argument
    if len(sys.argv) > 1:
        pdf_path = sys.argv[1]
    else:
        # Look for PDF files in the current directory
        pdf_files = [f for f in os.listdir('.') if f.lower().endswith('.pdf')]
        
        if not pdf_files:
            print("No PDF files found in the current directory.")
            print("Usage: python main.py [path_to_pdf_file]")
            return
        
        # If there's only one PDF file, use it
        if len(pdf_files) == 1:
            pdf_path = pdf_files[0]
            print(f"Using PDF file: {pdf_path}")
        else:
            # Let the user choose which PDF file to process
            print("Multiple PDF files found. Please choose one:")
            for i, file in enumerate(pdf_files, 1):
                print(f"{i}. {file}")
            
            try:
                choice = int(input("Enter the number of the file to process: "))
                if 1 <= choice <= len(pdf_files):
                    pdf_path = pdf_files[choice - 1]
                else:
                    print("Invalid choice.")
                    return
            except ValueError:
                print("Invalid input.")
                return
    
    # Create output filename based on input filename
    output_file = os.path.splitext(pdf_path)[0] + "_extracted.json"
    
    try:
        # Create extractor and process the PDF
        extractor = TenableWASPDFExtractor(pdf_path)
        print("Extracting text from PDF...")
        extractor.extract_text()
        
        print("Getting scan information...")
        scan_info = extractor.get_scan_info()
        print(f"Scan name: {scan_info.get('scan_name', 'Unknown')}")
        print(f"Scan date: {scan_info.get('scan_date', 'Unknown')}")
        
        print("Extracting vulnerabilities...")
        extractor.extract_vulnerabilities()
        
        print("Generating summary...")
        summary = extractor.generate_summary()
        print(f"Total vulnerabilities found: {summary['total_vulnerabilities']}")
        
        print(f"Saving results to {output_file}...")
        extractor.save_to_json(output_file)
        
        print("Done!")
        
    except Exception as e:
        print(f"Error processing the PDF: {str(e)}")
        
if __name__ == "__main__":
    main()
