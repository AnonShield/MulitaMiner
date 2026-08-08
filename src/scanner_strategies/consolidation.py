from typing import List, Dict

def deduplicate_by_name(vulnerabilities: list, field: str = "Name") -> list:
    """Remove duplicates by field, keeping the record with most filled fields."""
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
            def count_filled_fields(vuln):
                return sum(1 for k, val in vuln.items() if val not in [None, '', [], {}, 0])
            most_complete = max(group, key=count_filled_fields)
            result.append(most_complete)
    return result

def generate_consolidation_log(strategy_report: dict = None, description_filtering_removed: int = 0, 
                              all_groups: dict = None, vulnerabilities_input: int = 0,
                              vulnerabilities_after_strategy: int = 0, vulnerabilities_final: int = 0) -> str:
    """Build the human-readable consolidation log text."""
    lines = []
    lines.append("=" * 70)
    lines.append("CONSOLIDATION & DEDUPLICATION REPORT")
    lines.append("=" * 70)
    lines.append("")
    
    if strategy_report:
        lines.append(f"Strategy: {strategy_report.get('strategy_name', 'Unknown')}")
        lines.append(f"Description: {strategy_report.get('description', 'N/A')}")
        lines.append("")
        
        lines.append(f"INPUT VULNERABILITIES: {vulnerabilities_input}")
        lines.append("")
        
        lines.append("PROCESSING STAGE 1: Strategy-Specific Consolidation")
        lines.append(f"  Result: {vulnerabilities_after_strategy} vulnerabilities")
        lines.append(f"  Removed: {vulnerabilities_input - vulnerabilities_after_strategy} ({strategy_report.get('reason', 'consolidation')})")
        if strategy_report.get('note'):
            lines.append(f"  Note: {strategy_report['note']}")
        lines.append("")
        
        if description_filtering_removed > 0:
            lines.append("PROCESSING STAGE 2: Description Validation Filter")
            lines.append(f"  Removed: {description_filtering_removed} (empty or invalid descriptions)")
            lines.append(f"  Result: {vulnerabilities_final} vulnerabilities")
            lines.append("")
        
        lines.append(f"OUTPUT FINAL: {vulnerabilities_final} vulnerabilities (valid & saved)")
    else:
        lines.append(f"INPUT: {vulnerabilities_input} vulnerabilities")
        lines.append(f"OUTPUT: {vulnerabilities_final} vulnerabilities")
    
    lines.append("")
    lines.append("=" * 70)
    
    log_text = "\n".join(lines)

    if all_groups:
        log_text += "\nDETAIL: Vulnerability Groups\n"
        log_text += "-" * 70 + "\n"
        for idx, (key, group) in enumerate(all_groups.items(), 1):
            log_text += f"Group {idx}: Key = {repr(key)}\n"
            log_text += f"  Total vulnerabilities in group: {len(group)}\n"
            for i, v in enumerate(group, 1):
                nome = v.get('Name', 'NO NAME')
                porta = v.get('port', '')
                protocolo = v.get('protocol', '')
                severidade = v.get('severity', '')
                desc = v.get('description', '')
                log_text += f"    {i}. Name: {nome}\n"
                log_text += f"       Port: {porta} | Protocol: {protocolo} | Severity: {severidade}\n"
                if desc:
                    if isinstance(desc, list):
                        desc = ' '.join([str(d) for d in desc if d])
                    desc = str(desc).strip().replace('\n', ' ')
                    log_text += f"       Description: {desc[:150]}{'...' if len(desc)>150 else ''}\n"
                else:
                    log_text += f"       Description: (empty)\n"
            log_text += "\n"
        log_text += "=" * 70 + "\n"
    
    return log_text


def central_custom_allow_duplicates(vulnerabilities: list, profile_config: dict = None, allow_duplicates = True, custom_strategy: str = None, output_file: str = None) -> list:
    """Central deduplication/consolidation pipeline.

    The scanner strategy decides (via get_custom_activation_value) for which
    allow_duplicates value its custom logic runs; otherwise the default applies:
    True keeps everything, False dedups by Name. Also writes the consolidation
    and removed-items logs.
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

    if not output_file and profile_config and 'output_file' in profile_config:
        output_file = profile_config['output_file']
    if not output_file:
        output_file = 'output.json'
    
    dedup_log_path = os.path.splitext(output_file)[0] + '_deduplication_log.txt'
    removed_log_path = os.path.splitext(output_file)[0] + '_removed_log.txt'

    input_count = len(vulnerabilities)

    # Activation value can be a single bool or a collection of bools
    use_custom = False
    if strategy and hasattr(strategy, 'get_custom_activation_value') and hasattr(strategy, 'vulnerability_processing_logic'):
        custom_activation_value = strategy.get_custom_activation_value()

        if isinstance(custom_activation_value, (set, list, tuple)):
            use_custom = (custom_activation_value is not None and allow_duplicates in custom_activation_value)
        else:
            use_custom = (custom_activation_value is not None and allow_duplicates == custom_activation_value)

    if use_custom:
        print(f"[DEDUPLICATION] Custom mode: allow_duplicates={allow_duplicates} (scanner: {source})")
        result = strategy.vulnerability_processing_logic(vulnerabilities, allow_duplicates, profile_config)
        after_strategy_count = len(result)
        strategy_report = None
        if hasattr(strategy, 'get_consolidation_report'):
            strategy_report = strategy.get_consolidation_report(
                input_count=input_count,
                output_count=after_strategy_count,
                removed=input_count - after_strategy_count
            )
    else:
        print(f"[DEDUPLICATION] Default mode: allow_duplicates={allow_duplicates}")
        if allow_duplicates is True:
            result = vulnerabilities
            dedup_reason = "no deduplication (duplicates allowed)"
        else:
            result = deduplicate_by_name(vulnerabilities, field='Name')
            dedup_reason = "deduplicated by Name field"

        after_strategy_count = len(result)

        strategy_report = {
            'strategy_name': 'Default Behavior',
            'description': 'Default deduplication logic',
            'input_count': input_count,
            'output_count': after_strategy_count,
            'removed': input_count - after_strategy_count,
            'reason': dedup_reason
        }
    
    # Valid Name and description are required in all modes
    def has_valid_description(vuln):
        desc = vuln.get("description")
        if not desc:
            return False
        if isinstance(desc, list):
            return any(str(d).strip() for d in desc)
        return bool(str(desc).strip())

    def has_valid_name(vuln):
        name = vuln.get("Name")
        if not name:
            return False
        return bool(str(name).strip())

    valid_result = []
    removed = []
    for v in result:
        if has_valid_name(v) and has_valid_description(v):
            valid_result.append(v)
        else:
            removed.append(v)

    if removed:
        with open(removed_log_path, 'w', encoding='utf-8') as f:
            f.write(f"# LOG OF REMOVED VULNERABILITIES (missing valid Name or description)\n\n")
            for idx, v in enumerate(removed, 1):
                f.write(f"Removed {idx}:\n")
                f.write(json.dumps(v, ensure_ascii=False, indent=2))
                f.write("\n---\n")
        print(f"[DEDUPLICATION] Removed items log: {removed_log_path}")
    
    result = valid_result

    # Rebuild grouping for the log details
    from collections import defaultdict
    def make_hashable(val):
        if isinstance(val, list):
            return tuple(make_hashable(x) for x in val)
        elif isinstance(val, dict):
            return tuple(sorted((k, make_hashable(vv)) for k, vv in val.items()))
        else:
            return val
    grouped = defaultdict(list)
    for v in result:
        name_val = v.get('Name') or ''
        if isinstance(name_val, list):
            name_val = ' '.join(str(x) for x in name_val)
        name = str(name_val).strip()
        port = v.get('port')
        protocol = v.get('protocol')
        if name == 'Services':
            key = tuple(sorted((k, make_hashable(vv)) for k, vv in v.items()))
        else:
            key = (name, make_hashable(port), make_hashable(protocol))
        grouped[key].append(v)

    log_content = generate_consolidation_log(
        strategy_report=strategy_report,
        description_filtering_removed=len(removed),
        all_groups=grouped,
        vulnerabilities_input=input_count,
        vulnerabilities_after_strategy=after_strategy_count,
        vulnerabilities_final=len(result)
    )

    with open(dedup_log_path, 'w', encoding='utf-8') as f:
        f.write(log_content)
    print(f"[DEDUPLICATION] Consolidation log saved to: {dedup_log_path}")
    
    return result
