import re
import PyPDF2
import os
from datetime import datetime

class TenableWASPDFExtractor:
    """
    Class to extract information from TenableWAS PDF reports.
    """
    def __init__(self, pdf_path):
        """
        Initialize with the path to a TenableWAS PDF report.
        
        Args:
            pdf_path (str): Path to the PDF file
        """
        self.pdf_path = pdf_path
        self.extracted_text = ""
        self.vulnerabilities = []
        
    def extract_text(self):
        """
        Extract all text content from the PDF.
        
        Returns:
            str: Extracted text content
        """
        if not os.path.exists(self.pdf_path):
            raise FileNotFoundError(f"PDF file not found: {self.pdf_path}")
            
        try:
            with open(self.pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text = ""
                
                # Extract text from each page
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    text += page.extract_text()
                
                self.extracted_text = text
                return text
                
        except Exception as e:
            raise Exception(f"Error extracting text from PDF: {str(e)}")
    
    def get_scan_info(self):
        """
        Extract basic scan information like scan name, date, target, etc.
        
        Returns:
            dict: Dictionary containing scan information
        """
        info = {}
        
        if not self.extracted_text:
            self.extract_text()
            
        # Extract scan name
        scan_name_match = re.search(r"Web Application Scanning Detailed Scan Export:\s*(.*?)(?:\n|$)", self.extracted_text)
        if scan_name_match:
            info["scan_name"] = scan_name_match.group(1).strip()
            
        # Extract scan date
        date_match = re.search(r"(\w+\s+\d{1,2},\s+\d{4}\s+at\s+\d{1,2}:\d{2}\s+\(\w+\))", self.extracted_text)
        if date_match:
            date_str = date_match.group(1)
            info["scan_date"] = date_str
        
        # Extract contact info
        contact_match = re.search(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[-a-zA-Z0-9]*)", self.extracted_text)
        if contact_match:
            info["contact"] = contact_match.group(1).strip()
            
        return info
    
    def extract_vulnerabilities(self):
        """
        Extract vulnerability information from the PDF.
        
        Returns:
            list: List of dictionaries containing vulnerability information
        """
        if not self.extracted_text:
            self.extract_text()
            
        # Find vulnerability sections in the "Scan Results" table
        # First, extract the main vulnerability table to get proper names and plugin IDs
        results_section = re.search(r"Scan Results.*?Vulnerabilities.*?Severity\s+Plugin Id\s+Name\s+Family\s+Instances(.*?)(?:Page \d+ of \d+|$)", self.extracted_text, re.DOTALL)
        
        vulnerabilities = []
        vuln_map = {}  # Map of plugin ID to vulnerability name
        
        # Extract vulnerability details from the Scan Results table
        if results_section:
            results_text = results_section.group(1)
            # Extract vulnerability info from the table
            vuln_rows = re.finditer(r"(Critical|High|Medium|Low|Info)\s+(\d+)\s+([^\n]+?)\s+([^\n]+?)\s+\d+", results_text)
            
            # First try to extract full names from TOC
            toc_entries = {}
            toc_matches = re.finditer(r"([A-Za-z0-9\s\(\)<>\-./,'\"&;:]+?)\.{2,}\s+(\d+)", self.extracted_text[:5000])
            for toc_match in toc_matches:
                entry_name = toc_match.group(1).strip()
                if not any(skip in entry_name.lower() for skip in ["scan summary", "scan notes", "scan results", "table of contents", "instances"]):
                    toc_entries[entry_name.lower()] = entry_name
            
            for match in vuln_rows:
                severity = match.group(1).strip()
                plugin_id = match.group(2).strip()
                vuln_name = match.group(3).strip()
                family = match.group(4).strip() if len(match.groups()) >= 4 else ""
                
                # Try to find a more complete name in TOC or elsewhere in document
                complete_name = vuln_name
                
                # Check in TOC entries first
                for toc_key, toc_value in toc_entries.items():
                    if vuln_name.lower() in toc_key and len(toc_value) > len(vuln_name):
                        complete_name = toc_value
                        break
                
                # If not found in TOC, search elsewhere
                if complete_name == vuln_name:
                    full_name_match = re.search(r"\b" + re.escape(vuln_name) + r"\s+[^\n]{5,50}", self.extracted_text)
                    if full_name_match:
                        potential_name = full_name_match.group(0).strip()
                        if len(potential_name) > len(vuln_name) and len(potential_name) < 100:
                            complete_name = potential_name
                
                # Remove trailing dots from vulnerability name
                vuln_name = complete_name.rstrip('.')
                
                # Store in the map for later reference
                vuln_map[plugin_id] = {
                    "name": vuln_name,
                    "severity": severity,
                    "family": family
                }
        
        # Instead of searching through the whole document, let's just use the vulnerability map 
        # that we already extracted from the results table
        for plugin_id, info in vuln_map.items():
            vuln_name = info["name"]
            severity = info["severity"]
            
            # Search for this specific plugin ID in the document
            vuln_section = re.search(r"(?:VULNERABILITY PLUGIN ID|PLUGIN ID)\s+" + plugin_id + r".*?Description(.*?)(?:Solution|See Also|Risk Information)", self.extracted_text, re.DOTALL)
            
            if vuln_section:
                description = vuln_section.group(1).strip()
                
                # Extract solution if available
                solution_match = re.search(r"Solution(.*?)(?:See Also|Risk Information|Synopsis|VULNERABILITY PLUGIN ID|PLUGIN ID|Page \d+ of \d+)", self.extracted_text[vuln_section.end():vuln_section.end()+3000], re.DOTALL)
                solution = solution_match.group(1).strip() if solution_match else "No solution provided"
                
                # Extract risk information if available
                risk_info_match = re.search(r"Risk Information(.*?)(?:See Also|Solution|Synopsis|VULNERABILITY PLUGIN ID|PLUGIN ID|Page \d+ of \d+)", self.extracted_text[vuln_section.end():vuln_section.end()+5000], re.DOTALL)
                risk_information = risk_info_match.group(1).strip() if risk_info_match else ""
                
                # If risk info wasn't found after the description, try looking elsewhere in the document
                if not risk_information:
                    alt_risk_match = re.search(r"Plugin ID\s+" + plugin_id + r".*?Risk Information(.*?)(?:See Also|Solution|Synopsis|Description|VULNERABILITY PLUGIN ID|PLUGIN ID|Page \d+ of \d+)", self.extracted_text, re.DOTALL)
                    risk_information = alt_risk_match.group(1).strip() if alt_risk_match else "No risk information available"
            else:
                description = "No detailed description available"
                solution = "No solution provided"
                risk_information = "No risk information available"
            
            # Store the vulnerability information
            vuln_info = {
                "name": vuln_name,
                "severity": severity,
                "plugin_id": plugin_id,
                "description": description,
                "solution": solution,
                "risk_information": risk_information,
                "family": info.get("family", "")
            }
            
            vulnerabilities.append(vuln_info)
            
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def save_to_json(self, output_file):
        """
        Save extracted vulnerabilities to a JSON file.
        
        Args:
            output_file (str): Path to output JSON file
        """
        import json
        
        if not self.vulnerabilities:
            self.extract_vulnerabilities()
            
        scan_info = self.get_scan_info()
        
        data = {
            "scan_info": scan_info,
            "vulnerabilities": self.vulnerabilities,
            "extracted_at": datetime.now().isoformat()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            
        return output_file
    
    def generate_summary(self):
        """
        Generate a summary of the vulnerabilities found.
        
        Returns:
            dict: Summary statistics
        """
        if not self.vulnerabilities:
            self.extract_vulnerabilities()
            
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_counts": severity_counts
        }