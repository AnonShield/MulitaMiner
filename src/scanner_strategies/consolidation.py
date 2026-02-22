def deduplicate_by_name(vulnerabilities: list, field: str = "Name") -> list:
    """
    Remove duplicatas baseando-se no campo especificado, mantendo a vulnerabilidade mais completa (mais campos preenchidos).
    """
    if not vulnerabilities:
        return []
    from collections import defaultdict
    grouped = defaultdict(list)
    for v in vulnerabilities:
        key = v.get(field, None) if isinstance(v, dict) else None
        grouped[key].append(v)
    result = []
    for group in grouped.values():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Mantém a mais completa (mais campos não vazios)
            def count_filled_fields(vuln):
                return sum(1 for k, val in vuln.items() if val not in [None, '', [], {}, 0])
            most_complete = max(group, key=count_filled_fields)
            result.append(most_complete)
    return result

def central_custom_allow_duplicates(vulnerabilities: list, profile_config: dict = None, allow_duplicates = True, custom_strategy: str = None, output_file: str = None) -> list:
    """
    Pipeline central para deduplicação/consolidação:
    - Sempre consulta registry.py para estratégia customizada.
    - allow_duplicates=True/False: passado para a estratégia, que decide o comportamento.
    - Se não houver estratégia, usa deduplicate_by_name padrão.
    Gera logs de merge, deduplicação e removed para todos os scanners.
    """
    from .registry import get_strategy
    import os
    import json
    source = None
    if vulnerabilities and isinstance(vulnerabilities[0], dict):
        source = vulnerabilities[0].get('source', None)
    if not source and profile_config and 'reader' in profile_config:
        source = profile_config['reader']
    strategy = get_strategy(source) if source else None
    # Usa sempre o output_file explícito
    if not output_file and profile_config and 'output_file' in profile_config:
        output_file = profile_config['output_file']
    if not output_file:
        output_file = 'output.json'
    # Usa o caminho completo do arquivo de saída
    merge_log_path = os.path.splitext(output_file)[0] + '_merge_log.txt'
    dedup_log_path = os.path.splitext(output_file)[0] + '_deduplication_log.txt'
    removed_log_path = os.path.splitext(output_file)[0] + '_removed_log.txt'
    # Remover vulnerabilidades sem descrição válida
    def has_valid_description(vuln):
        desc = vuln.get("description")
        if not desc:
            return False
        if isinstance(desc, list):
            return any(str(d).strip() for d in desc)
        return bool(str(desc).strip())
    valid_vulns = []
    removed = []
    for v in vulnerabilities:
        if has_valid_description(v):
            valid_vulns.append(v)
        else:
            removed.append(v)
    # Salva log de removidos
    if removed:
        with open(removed_log_path, 'w', encoding='utf-8') as f:
            f.write(f"# LOG DE VULNERABILIDADES REMOVIDAS (sem descrição válida)\n\n")
            for idx, v in enumerate(removed, 1):
                f.write(f"Removida {idx}:\n")
                f.write(json.dumps(v, ensure_ascii=False, indent=2))
                f.write("\n---\n")
        print(f"🗑 Log de vulnerabilidades removidas salvo em: {removed_log_path}")
    # Deduplicação/consolidação
    if strategy and hasattr(strategy, 'vulnerability_processing_logic'):
        print(f"🔎 Modo allow_duplicates: {'True' if allow_duplicates else 'False'} (custom: {source})")
        result = strategy.vulnerability_processing_logic(valid_vulns, allow_duplicates, profile_config)
        # Salva log de merge/deduplicação
        # Conteúdo explicativo para logs

        def log_intro(tipo, total_in, total_out):
            return (
                f"# LOG DE {tipo.upper()} DE VULNERABILIDADES\n"
                f"Este arquivo lista todas as vulnerabilidades consideradas duplicatas e agrupadas durante o processo.\n"
                f"Cada grupo é identificado por uma chave composta (ex: nome, porta, protocolo).\n"
                f"Apenas a vulnerabilidade mais completa e com descrição válida foi mantida em cada grupo.\n\n"
                f"Total de grupos de duplicatas: {total_out}\n"
                f"Total de vulnerabilidades agrupadas (removidas): {total_in - total_out}\n\n"
            )
        
        def log_grupos(result, grouped):
            linhas = []
            for idx, (key, group) in enumerate(grouped.items(), 1):
                linhas.append(f"Grupo {idx}: Chave = {repr(key)}")
                linhas.append(f"  Total de duplicatas neste grupo: {len(group)}")
                for i, v in enumerate(group, 1):
                    nome = v.get('Name', 'SEM NOME')
                    porta = v.get('port', '')
                    protocolo = v.get('protocol', '')
                    severidade = v.get('severity', '')
                    desc = v.get('description', '')
                    linhas.append(f"    {i}. Nome: {nome}")
                    linhas.append(f"       Porta: {porta} | Protocolo: {protocolo} | Severidade: {severidade}")
                    if desc:
                        if isinstance(desc, list):
                            desc = ' '.join([str(d) for d in desc if d])
                        desc = str(desc).strip().replace('\n', ' ')
                        linhas.append(f"       Descrição: {desc[:200]}{'...' if len(desc)>200 else ''}")
                    else:
                        linhas.append(f"       Descrição: (vazia)")
                linhas.append("")
            return '\n'.join(linhas)
        # Reconstruir agrupamento para log
        from collections import defaultdict
        grouped = defaultdict(list)
        for v in result:
            name = v.get('Name', '').strip()
            port = v.get('port')
            protocol = v.get('protocol')
            if name == 'Services':
                def make_hashable(val):
                    if isinstance(val, list):
                        return tuple(val)
                    elif isinstance(val, dict):
                        return tuple(sorted(val.items()))
                    else:
                        return val
                key = tuple(sorted((k, make_hashable(vv)) for k, vv in v.items()))
            else:
                key = (name, port, protocol)
            grouped[key].append(v)
        # Só gera log de merge se a estratégia realmente faz merge (ex: Tenable, mas NÃO OpenVAS)
        if source and hasattr(strategy, 'has_merge_log') and strategy.has_merge_log:
            with open(merge_log_path, 'w', encoding='utf-8') as f:
                f.write(log_intro('merge/consolidação', len(valid_vulns), len(result)))
                f.write(log_grupos(result, grouped))
                f.write(f"Resumo final:\nTotal de grupos de duplicatas: {len(result)}\nTotal de vulnerabilidades agrupadas (removidas): {len(valid_vulns) - len(result)}\n")
            print(f"📄 Log de merge salvo em: {merge_log_path}")
        with open(dedup_log_path, 'w', encoding='utf-8') as f:
            f.write(log_intro('deduplicação', len(valid_vulns), len(result)))
            f.write(log_grupos(result, grouped))
            f.write(f"Resumo final:\nTotal de grupos de duplicatas: {len(result)}\nTotal de vulnerabilidades agrupadas (removidas): {len(valid_vulns) - len(result)}\n")
        print(f"📄 Log de deduplicação salvo em: {dedup_log_path}")
        return result
    # fallback: deduplicação simples
    print(f"🔎 Modo allow_duplicates: {'True' if allow_duplicates else 'False'} (default)")
    field = 'Name'
    if profile_config and 'consolidation_field' in profile_config:
        field = profile_config['consolidation_field']
    if allow_duplicates is True:
        result = valid_vulns
    else:
        result = deduplicate_by_name(valid_vulns, field)
    # Log explicativo apenas para deduplicação (default)
    def log_intro(tipo, total_in, total_out):
        return (
            f"# LOG DE {tipo.upper()} DE VULNERABILIDADES\n"
            f"Este arquivo lista todas as vulnerabilidades consideradas duplicatas e agrupadas durante o processo.\n"
            f"Cada grupo é identificado por uma chave composta (ex: nome, porta, protocolo).\n"
            f"Apenas a vulnerabilidade mais completa e com descrição válida foi mantida em cada grupo.\n\n"
            f"Total de grupos de duplicatas: {total_out}\n"
            f"Total de vulnerabilidades agrupadas (removidas): {total_in - total_out}\n\n"
        )
    def log_grupos(result, grouped):
        linhas = []
        for idx, (key, group) in enumerate(grouped.items(), 1):
            linhas.append(f"Grupo {idx}: Chave = {repr(key)}")
            linhas.append(f"  Total de duplicatas neste grupo: {len(group)}")
            for i, v in enumerate(group, 1):
                nome = v.get('Name', 'SEM NOME')
                porta = v.get('port', '')
                protocolo = v.get('protocol', '')
                severidade = v.get('severity', '')
                desc = v.get('description', '')
                linhas.append(f"    {i}. Nome: {nome}")
                linhas.append(f"       Porta: {porta} | Protocolo: {protocolo} | Severidade: {severidade}")
                if desc:
                    if isinstance(desc, list):
                        desc = ' '.join([str(d) for d in desc if d])
                    desc = str(desc).strip().replace('\n', ' ')
                    linhas.append(f"       Descrição: {desc[:200]}{'...' if len(desc)>200 else ''}")
                else:
                    linhas.append(f"       Descrição: (vazia)")
            linhas.append("")
        return '\n'.join(linhas)
    # Reconstruir agrupamento para log
    from collections import defaultdict
    grouped = defaultdict(list)
    for v in result:
        key = v.get(field, None) if isinstance(v, dict) else None
        grouped[key].append(v)
    with open(dedup_log_path, 'w', encoding='utf-8') as f:
        f.write(log_intro('deduplicação', len(valid_vulns), len(result)))
        f.write(log_grupos(result, grouped))
        f.write(f"Resumo final:\nTotal de grupos de duplicatas: {len(result)}\nTotal de vulnerabilidades agrupadas (removidas): {len(valid_vulns) - len(result)}\n")
    print(f"📄 Log de deduplicação salvo em: {dedup_log_path}")
    return result
def remove_duplicates_by_key(vulnerabilities: list, key: str = "Name", log_path: str = None) -> list:
    """
    Remove duplicatas de vulnerabilidades com base em uma chave específica.
    Se log_path for fornecido, salva um log das duplicatas removidas.
    """
    seen = set()
    unique = []
    removed = []
    for v in vulnerabilities:
        val = v.get(key, None) if isinstance(v, dict) else None
        if val is not None and val not in seen:
            seen.add(val)
            unique.append(v)
        else:
            removed.append(v)
    if log_path and removed:
        import json
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"# LOG DE DUPLICATAS REMOVIDAS POR CHAVE '{key}'\n\n")
            for idx, v in enumerate(removed, 1):
                f.write(f"Removida {idx}:\n")
                f.write(json.dumps(v, ensure_ascii=False, indent=2))
                f.write("\n---\n")
    return unique

def consolidate_duplicates_with_logs(vulnerabilities: List[Dict], profile_config: Dict = None):
    """
    Consolida vulnerabilidades removendo duplicatas e mesclando URLs, gerando logs detalhados de removidos e merges.
    Retorna: (final_vulns, removed_vulns, merged_pairs)
    """
    if not vulnerabilities:
        return [], [], []

    # 1. Remover vulnerabilidades sem descrição válida
    def has_valid_description(vuln):
        desc = vuln.get("description")
        if not desc:
            return False
        if isinstance(desc, list):
            return any(str(d).strip() for d in desc)
        return bool(str(desc).strip())

    valid_vulns = []
    removed = []
    for v in vulnerabilities:
        if has_valid_description(v):
            valid_vulns.append(v)
        else:
            removed.append(v)

    # 2. Consolidar duplicatas usando a lógica centralizada
    consolidated = consolidate_vulnerabilities(valid_vulns, profile_config)

    # 3. Gerar pares mesclados para log (grupos de vulnerabilidades que foram consolidados)
    # Para cada grupo consolidado, se houver mais de uma vulnerabilidade original, considera merge
    # (Implementação simples: agrupa por chave de consolidação e compara tamanho do grupo)
    from collections import defaultdict
    merged_pairs = []
    name_field = None
    if consolidated:
        # Detecta campo de chave
        sample = consolidated[0]
        for k in ["name_consolidated", "definition.name", "Name"]:
            if k in sample:
                name_field = k
                break
        if not name_field:
            name_field = "Name"

    group_map = defaultdict(list)
    for v in valid_vulns:
        key = v.get(name_field, '').strip().lower() if name_field else ''
        group_map[key].append(v)

    for group in group_map.values():
        if len(group) > 1:
            merged_pairs.append(group)

    return consolidated, removed, merged_pairs

from typing import List, Dict
from .registry import get_strategy

def consolidate_vulnerabilities(vulnerabilities: List[Dict], profile_config: Dict = None) -> List[Dict]:
    """
    Consolida vulnerabilidades usando a estratégia do scanner detectado.
    Modular, extensível e centralizado.
    """
    if not vulnerabilities:
        return []
    # Agrupa por source
    from collections import defaultdict
    by_source = defaultdict(list)
    for vuln in vulnerabilities:
        source = vuln.get('source', 'UNKNOWN')
        by_source[source].append(vuln)
    consolidated = []
    for source, vulns in by_source.items():
        strategy = get_strategy(source)
        if not strategy:
            consolidated.extend(vulns)
            continue
        if not strategy.should_consolidate():
            consolidated.extend(vulns)
            continue
        # Agrupa e consolida por base name/chave
        if source == 'OPENVAS':
            by_key = defaultdict(list)
            for vuln in vulns:
                name = vuln.get('Name', '').strip()
                port = vuln.get('port')
                protocol = vuln.get('protocol')
                if name:
                    key = (name, port, protocol)
                    by_key[key].append(vuln)
            for key, group in by_key.items():
                result = strategy.consolidate_group(group)
                consolidated.extend(result)
        else:
            by_name = defaultdict(list)
            for vuln in vulns:
                name = vuln.get('Name', '').strip()
                if name:
                    base_name = strategy.get_base_name(name)
                    by_name[base_name].append(vuln)
            for base_name, group in by_name.items():
                result = strategy.consolidate_group(group, profile_config)
                consolidated.extend(result)
    return consolidated
