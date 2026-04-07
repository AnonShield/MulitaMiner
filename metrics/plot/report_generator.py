"""
Report generation using Jinja2 templates.
Renders comprehensive HTML metrics reports with Chart.js.
"""

import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from typing import Dict, Any


class ReportGenerator:
    """Generate HTML reports from Jinja2 templates."""
    
    def __init__(self, template_dir=None):
        """
        Initialize report generator.
        
        Args:
            template_dir: Directory containing Jinja2 templates.
                         If None, defaults to metrics/plot directory
        """
        if template_dir is None:
            template_dir = os.path.dirname(os.path.abspath(__file__))
        
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))
    
    def generate_metrics_report(
        self,
        output_file: str,
        report_date: str,
        baselines: list,
        models: list,
        bert: str,
        rouge: str,
        det: str,
        stacked: str,
        results_dir: str = 'results_runs',
        has_bert: bool = True,
        has_rouge: bool = True,
        has_det: bool = True,
        has_stacked: bool = True,
        matched_rate: str = '{}',
        recall: str = '{}',
        absent_nonexist: str = '{}',
        has_matched: bool = False,
        has_recall: bool = False,
        has_absent_nonexist: bool = False,
        **kwargs
    ):
        """
        Render metrics report HTML with Chart.js.
        
        Args:
            output_file: Path to output HTML file
            report_date: Report generation date
            baselines: List of baseline names
            models: List of model/LLM names
            bert: JSON string of BERT data
            rouge: JSON string of ROUGE data
            det: JSON string of deterministic data
            stacked: JSON string of similarity stacked data
            results_dir: Results directory path
            has_bert: Whether BERT data is available
            has_rouge: Whether ROUGE data is available
            has_det: Whether deterministic data is available
            has_stacked: Whether similarity distribution data is available
            matched_rate: JSON string of matched rate data
            absent_nonexist: JSON string of absent/non-existent data
            has_matched: Whether matched rate data is available
            has_absent_nonexist: Whether absent/non-existent data is available
        """
        template = self.env.get_template('metrics_report_template_en.jinja2')
        
        html_content = template.render(
            report_date=report_date,
            baselines=baselines,
            models=models,
            bert_data=bert,
            rouge_data=rouge,
            det_data=det,
            stacked_data=stacked,
            matched_rate=matched_rate,
            recall=recall,
            absent_nonexist=absent_nonexist,
            results_dir=results_dir,
            has_bert=has_bert,
            has_rouge=has_rouge,
            has_det=has_det,
            has_stacked=has_stacked,
            has_matched=has_matched,
            has_recall=has_recall,
            has_absent_nonexist=has_absent_nonexist,
        )
        
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
