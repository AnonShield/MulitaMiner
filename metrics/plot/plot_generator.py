"""
Plotly-based graph generation for metrics reporting.
Supports interactive visualizations in HTML and selective PNG export.
"""

import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ============= THEME COLORS (matching experiments_report_template.html) =============
THEME_COLORS = {
    'bg': '#0a0e1a',
    'surface': '#111827',
    'surface2': '#1a2235',
    'surface3': '#0d1526',
    'border': '#1e2d45',
    'border2': '#263352',
    'accent': '#00e5ff',      # cyan
    'accent2': '#7c3aed',     # purple
    'accent3': '#10b981',     # green
    'accent4': '#f59e0b',     # amber
    'accent5': '#f43f5e',     # rose
    'text': '#e2e8f0',
    'muted': '#64748b',
    'muted2': '#94a3b8',
}

MODEL_COLORS = {
    'DeepSeek': '#00e5ff',
    'GPT-4': '#7c3aed',
    'GPT-5': '#10b981',
    'LLaMA 3': '#f59e0b',
    'LLaMA 4': '#f43f5e',
}

# Similarity categories colors
SIMILARITY_COLORS = {
    'Highly Similar': '#10b981',
    'Moderately Similar': '#00e5ff',
    'Slightly Similar': '#f59e0b',
    'Divergent': '#f43f5e',
    'Absent': '#64748b',
}


class PlotlyTheme:
    """Plotly styling consistent with dark theme template."""
    
    @staticmethod
    def get_layout(**kwargs):
        """Get base layout with theme colors."""
        default = dict(
            template='plotly_dark',
            plot_bgcolor=THEME_COLORS['surface'],
            paper_bgcolor=THEME_COLORS['bg'],
            font=dict(
                family='Space Mono, monospace',
                size=11,
                color=THEME_COLORS['text'],
            ),
            xaxis=dict(
                showgrid=True,
                gridwidth=1,
                gridcolor=THEME_COLORS['border'],
                zeroline=False,
                color=THEME_COLORS['muted'],
            ),
            yaxis=dict(
                showgrid=True,
                gridwidth=1,
                gridcolor=THEME_COLORS['border'],
                zeroline=False,
                color=THEME_COLORS['muted'],
            ),
            hovermode='closest',
            margin=dict(l=60, r=40, t=60, b=50),
        )
        default.update(kwargs)
        return default


class MetricsPlotter:
    """Generate Plotly charts for metrics evaluation."""
    
    def __init__(self, output_dir='plot_runs', export_png_only=None):
        """
        Initialize plotter.
        
        Args:
            output_dir: Directory for HTML and PNG outputs
            export_png_only: List of chart types to export as PNG.
                             If None, defaults to ['heatmap', 'stacked_similarity', 'matched_rate']
        """
        self.output_dir = output_dir
        self.export_png_only = export_png_only or ['heatmap', 'stacked_similarity', 'matched_rate']
        os.makedirs(output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.charts = {}  # Store chart data for reporting
    
    def generate_chart_data(self, fig, chart_type: str, filename_base: str, title: str = None):
        """
        Generate chart HTML string and optionally PNG.
        
        Args:
            fig: Plotly figure
            chart_type: Type of chart (for filtering PNG export)
            filename_base: Base filename without extension
            title: Optional chart title for display
            
        Returns:
            Dict with {html_string, title, png_path (optional)}
        """
        # Generate HTML string with inline plotly
        html_string = fig.to_html(include_plotlyjs='cdn', div_id=filename_base)
        
        # Optionally export PNG
        png_path = None
        if chart_type in self.export_png_only:
            try:
                png_path = os.path.join(self.output_dir, f"{filename_base}.png")
                fig.write_image(png_path, width=1400, height=700, scale=2)
            except Exception as e:
                pass  # Silent fail for PNG
        
        return {
            'html_string': html_string,
            'title': title or filename_base,
            'png_path': png_path,
        }
    
    # ============ HEATMAPS ============
    def heatmap_scores(self, baseline: str, metric: str, data: Dict[str, Dict[str, float]]):
        """Generate heatmap of scores (BERT/ROUGE) for models × fields."""
        df = pd.DataFrame(data).T
        
        fig = go.Figure(data=go.Heatmap(
            z=df.values,
            x=df.columns,
            y=df.index,
            colorscale=[
                [0.0, '#f43f5e'],      # rose (low)
                [0.5, '#f59e0b'],      # amber (mid)
                [0.75, '#10b981'],     # green 
                [1.0, '#00e5ff'],      # cyan (high)
            ],
            hovertemplate='<b>%{y}</b><br>%{x}<br>Score: %{z:.3f}<extra></extra>',
            colorbar=dict(
                title='Score',
                thickness=15,
                len=0.7,
                tickcolor=THEME_COLORS['text'],
            ),
        ))
        
        metric_label = 'BERTScore' if metric == 'bert' else 'ROUGE-L'
        fig.update_layout(
            title=f'{metric_label} Scores Heatmap — {baseline}',
            xaxis_title='Field',
            yaxis_title='Model',
            **PlotlyTheme.get_layout(height=500),
        )
        
        filename = f"heatmap_{metric}_{baseline}_{self.timestamp}"
        title = f'{metric_label} Scores Heatmap — {baseline}'
        return self.generate_chart_data(fig, 'heatmap', filename, title)
    
    # ============ STACKED BARS ============
    def similarity_distribution_stacked_bar(self, scanner: str, metric: str, data: Dict[str, Dict[str, List[float]]]):
        """Generate stacked bar chart for similarity categories."""
        categories = ['Highly Similar', 'Moderately Similar', 'Slightly Similar', 'Divergent', 'Absent']
        colors_list = [SIMILARITY_COLORS[cat] for cat in categories]
        
        fig = go.Figure()
        
        # Flatten data structure for stacked bar
        x_labels = []
        for baseline, llm_data in data.items():
            for llm, values in llm_data.items():
                x_labels.append(f"{llm}<br>{baseline}")
        
        # Add traces for each category
        for idx, category in enumerate(categories):
            y_values = []
            for baseline, llm_data in data.items():
                for llm, values in llm_data.items():
                    y_values.append(values[idx] if idx < len(values) else 0)
            
            fig.add_trace(go.Bar(
                x=x_labels,
                y=y_values,
                name=category,
                marker=dict(color=colors_list[idx]),
                hovertemplate='<b>%{x}</b><br>' + category + ': %{y:.1f}%<extra></extra>',
            ))
        
        metric_label = 'BERT' if metric == 'bert' else 'ROUGE'
        layout_kwargs = PlotlyTheme.get_layout(height=600)
        layout_kwargs['title'] = f'Similarity Distribution — {scanner} ({metric_label})'
        layout_kwargs['barmode'] = 'stack'
        layout_kwargs['xaxis_title'] = 'LLM — Baseline'
        layout_kwargs['xaxis']['tickangle'] = -45
        layout_kwargs['yaxis']['range'] = [0, 100]
        layout_kwargs['yaxis']['title'] = 'Distribution (%)'
        
        fig.update_layout(**layout_kwargs)
        
        filename = f"stacked_similarity_{scanner}_{metric}_{self.timestamp}"
        title = f'Similarity Distribution — {scanner} ({metric_label})'
        return self.generate_chart_data(fig, 'stacked_similarity', filename, title)
    
    # ============ MATCHED RATE TRENDS ============
    def matched_rate_curve(self, scanner: str, baseline: str, metric: str, data: Dict[str, np.ndarray]):
        """Generate line chart for matched rate trends across runs."""
        fig = go.Figure()
        
        for llm, run_values in data.items():
            runs = np.arange(1, len(run_values) + 1)
            
            fig.add_trace(go.Scatter(
                x=runs,
                y=run_values,
                name=llm,
                mode='lines+markers',
                line=dict(
                    color=MODEL_COLORS.get(llm, '#00e5ff'),
                    width=2,
                ),
                marker=dict(size=5),
                hovertemplate=f'<b>{llm}</b><br>Run %{{x}}<br>Matched: %{{y:.3f}}<extra></extra>',
            ))
        
        metric_label = 'BERT' if metric == 'bert' else 'ROUGE'
        layout_kwargs = PlotlyTheme.get_layout(height=500)
        layout_kwargs['title'] = f'Matched Rate Trend — {scanner} | {baseline} ({metric_label})'
        layout_kwargs['xaxis_title'] = 'Run Number'
        layout_kwargs['yaxis']['range'] = [0, 1.0]
        layout_kwargs['yaxis']['title'] = 'Matched Rate'
        
        fig.update_layout(**layout_kwargs)
        
        filename = f"matched_rate_{scanner}_{baseline}_{metric}_{self.timestamp}"
        title = f'Matched Rate Trend — {scanner} | {baseline} ({metric_label})'
        return self.generate_chart_data(fig, 'matched_rate', filename, title)
    
    # ============ ENTITY METRICS GROUPED BAR ============
    def entity_metrics_grouped_bar(self, scanner: str, baseline: str, field: str, data: Dict[str, Dict[str, float]]):
        """Generate grouped bar chart for entity metrics (F1, Precision, Recall)."""
        metrics = list(data.keys())
        models = list(next(iter(data.values())).keys())
        
        fig = go.Figure()
        
        for idx, metric in enumerate(metrics):
            values = [data[metric][m] for m in models]
            fig.add_trace(go.Bar(
                x=models,
                y=values,
                name=metric,
                marker=dict(color=THEME_COLORS[['accent', 'accent3', 'accent4'][idx % 3]]),
                hovertemplate='<b>%{x}</b><br>' + metric + ': %{y:.3f}<extra></extra>',
            ))
        
        fig.update_layout(
            title=f'Entity Metrics — {scanner} | {baseline} | {field}',
            barmode='group',
            xaxis_title='Model',
            yaxis_title='Score',
            **PlotlyTheme.get_layout(height=500),
        )
        fig.update_yaxes(range=[0, 1.0])
        
        filename = f"entity_metrics_{scanner}_{baseline}_{field}_{self.timestamp}"
        title = f'Entity Metrics — {scanner} | {baseline} | {field}'
        return self.generate_chart_data(fig, 'entity_metrics', filename, title)
