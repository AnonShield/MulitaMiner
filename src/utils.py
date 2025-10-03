"""
Utility functions and classes for PDF Vulnerability Extractor.

This module provides result processing, file validation, and JSONL handling utilities.
"""

import json
import logging
from typing import List, Dict, Any
from pathlib import Path


class ResultProcessor:
    """Processes and consolidates vulnerability extraction results."""
    
    @staticmethod
    def ensure_output_directory(output_dir: str) -> None:
        """Ensure output directory exists.
        
        Args:
            output_dir: Output directory path
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        # logging.info(f"Output directory ready: {output_dir}")  # Commented to reduce log noise
    
    @staticmethod
    def load_vulnerabilities_from_jsonl(jsonl_path: str) -> List[Dict[str, Any]]:
        """Load all vulnerabilities from JSONL file.
        
        Args:
            jsonl_path: Path to JSONL file
            
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        if not Path(jsonl_path).exists():
            logging.warning(f"JSONL file not found: {jsonl_path}")
            return vulnerabilities
        
        try:
            with open(jsonl_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logging.error(f"Error reading JSONL file: {e}")
        
        return vulnerabilities
    
    @staticmethod
    def remove_duplicates(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerabilities based on name and plugin_id.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List with duplicates removed
        """
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create unique key from name and plugin_id
            key = (vuln.get('name', ''), vuln.get('plugin_id', ''))
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        logging.info(f"Removed {len(vulnerabilities) - len(unique)} duplicates")
        return unique
    
    @staticmethod
    def save_final_json(vulnerabilities: List[Dict[str, Any]], output_path: str) -> None:
        """Save final consolidated vulnerabilities to JSON file.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            output_path: Path for output JSON file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
            logging.info(f"Final results saved: {len(vulnerabilities)} unique vulnerabilities")
        except Exception as e:
            logging.error(f"Error saving final JSON: {e}")
            raise
    
    @staticmethod
    def get_severity_statistics(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity distribution statistics.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary with severity counts
        """
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    @staticmethod
    def log_statistics(vulnerabilities: List[Dict[str, Any]]) -> None:
        """Log vulnerability statistics.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        """
        severity_stats = ResultProcessor.get_severity_statistics(vulnerabilities)
        
        logging.info(f"Processing completed: {len(vulnerabilities)} total vulnerabilities")
        logging.info("Statistics by severity:")
        for severity, count in sorted(severity_stats.items()):
            logging.info(f"  {severity}: {count}")
    
    @staticmethod
    def consolidate_results(jsonl_path: str, output_dir: str) -> str:
        """Consolidate JSONL results into final JSON file.
        
        Args:
            jsonl_path: Path to JSONL file
            output_dir: Output directory
            
        Returns:
            Path to final JSON file
        """
        logging.info("Consolidating results and removing duplicates...")
        
        # Load vulnerabilities from JSONL
        vulnerabilities = ResultProcessor.load_vulnerabilities_from_jsonl(jsonl_path)
        
        # Remove duplicates
        unique_vulnerabilities = ResultProcessor.remove_duplicates(vulnerabilities)
        
        # Save final JSON
        final_path = Path(output_dir) / "vulnerabilities_extracted.json"
        ResultProcessor.save_final_json(unique_vulnerabilities, str(final_path))
        
        return str(final_path)


class FileValidator:
    """Validates file paths and extensions."""
    
    @staticmethod
    def validate_file_exists(file_path: str, file_type: str = "file") -> bool:
        """Validate that a file exists.
        
        Args:
            file_path: Path to file
            file_type: Type description for logging
            
        Returns:
            True if file exists, False otherwise
        """
        if not Path(file_path).exists():
            logging.error(f"{file_type.capitalize()} '{file_path}' not found")
            return False
        return True
    
    @staticmethod
    def ensure_file_extension(file_path: str, expected_ext: str) -> bool:
        """Check if file has expected extension.
        
        Args:
            file_path: Path to file
            expected_ext: Expected extension (e.g., '.pdf')
            
        Returns:
            True if extension matches, False otherwise
        """
        return Path(file_path).suffix.lower() == expected_ext.lower()


class JSONLHandler:
    """Handles JSONL file operations for incremental saving."""
    
    def __init__(self, file_path: str):
        """Initialize JSONL handler.
        
        Args:
            file_path: Path to JSONL file
        """
        self.file_path = file_path
        self._initialize_file()
    
    def _initialize_file(self) -> None:
        """Initialize JSONL file."""
        try:
            # Create file if it doesn't exist
            Path(self.file_path).touch()
            logging.info(f"JSONL file initialized: {self.file_path}")
        except Exception as e:
            logging.error(f"Error initializing JSONL file: {e}")
            raise
    
    def append_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Append vulnerability to JSONL file.
        
        Args:
            vulnerability: Vulnerability dictionary
        """
        try:
            with open(self.file_path, 'a', encoding='utf-8') as f:
                json.dump(vulnerability, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            logging.error(f"Error appending to JSONL: {e}")
            raise