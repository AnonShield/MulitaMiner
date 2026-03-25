import argparse

def parse_arguments() -> argparse.Namespace:
    """Parse argumentos da linha de comando para extração principal."""
    parser = argparse.ArgumentParser(
        description='Extrai vulnerabilidades de relatórios PDF usando LLM'
    )
    # Grupo principal de argumentos
    parser.add_argument('--input', required=True, help='Caminho para o arquivo PDF')
    parser.add_argument('--scanner', default='default', 
                       help='Scanner de configuração (padrão: default)')
    parser.add_argument('--llm', default='gpt4', 
                       help='Nome do LLM a usar (padrão: gpt4)')
    
    # Grupo de opções de conversão
    conversion_group = parser.add_argument_group('Opções de Conversão')
    conversion_group.add_argument('--convert', choices=['csv', 'xlsx', 'tsv', 'all', 'none'],
                       default='none',
                       help='Converter saída JSON para formato específico. Use "all" ou "xlsx" para avaliação.')
    conversion_group.add_argument('--output-file', help='Nome do arquivo de saída (sem timestamp/id, sem extensão obrigatória)')
    conversion_group.add_argument('--output-dir', dest='output_dir',
                       help='Diretório de saída para arquivos convertidos')
    conversion_group.add_argument('--csv-delimiter', dest='csv_delimiter', default=',',
                       help='Delimitador para CSV (padrão: ,)')
    conversion_group.add_argument('--csv-encoding', dest='csv_encoding', default='utf-8-sig',
                       help='Codificação para CSV (padrão: utf-8-sig)')

    # Grupo de opções de avaliação de métricas
    evaluation_group = parser.add_argument_group('Opções de Avaliação de Métricas')
    evaluation_group.add_argument('--evaluate', action='store_true',
                                 help='Ativa a avaliação de métricas após a extração.')
    evaluation_group.add_argument('--baseline', type=str,
                                 help='Caminho para o arquivo .xlsx de ground truth para comparação.')
    evaluation_group.add_argument('--evaluation-method', choices=['bert', 'rouge'], default='bert',
                                 help='Método de avaliação a ser usado (padrão: bert).')
    evaluation_group.add_argument('--allow-duplicates', dest='allow_duplicates', action='store_true',
                                 help='Permite duplicatas legítimas na baseline durante avaliação')
    evaluation_group.add_argument('--run-experiments', action='store_true',
                                 help='Indica execução em lote (run_experiments.py) para salvar arquivos em results_runs.')
    
    return parser.parse_args()
