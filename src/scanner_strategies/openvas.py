import re
import os
from typing import List, Dict, Tuple
from .base import ScannerStrategy


def make_hashable(val):
    if isinstance(val, list):
        return tuple(make_hashable(x) for x in val)
    elif isinstance(val, dict):
        return tuple(sorted((k, make_hashable(vv)) for k, vv in val.items()))
    else:
        return val

class OpenVASStrategy(ScannerStrategy):
    scanner_name = 'openvas'
    requires_visual_layout = True
    has_merge_log = False
    
    def get_custom_activation_value(self) -> bool:
        """Custom consolidation activates when allow_duplicates=True"""
        return True
    
    # Header detection — supports three layouts the report can emit:
    #   (1) "High 443/tcp"                 → severity then port/proto (text PDF)
    #   (2) "443/tcp High"                 → port/proto then severity (markdown extractor — order reversed)
    #   (3) "2.1.1 Critical 8019/tcp"      → section-number prefix (markdown TOC numbering)
    # All three carry the same three groups: severity (group 'sev'), port (group 'port'),
    # protocol (group 'proto'). Optional `#+ ` prefix accepts markdown headings.
    _SEV = r"(?P<sev>Critical|High|Medium|Low|Log)"
    _PORT = r"(?P<port>\d+|general)"
    _PROTO = r"(?P<proto>[a-zA-Z0-9_-]+)"
    _SECTION_NUM = r"(?:\d+(?:\.\d+)*\s+)?"  # optional "2.1.1 " prefix
    HEADER_REGEX = re.compile(
        rf"^(?:#+\s+)?{_SECTION_NUM}{_SEV}\s+{_PORT}/{_PROTO}",
        re.IGNORECASE,
    )
    # Alternative order: port/proto first, severity second (markdown layout).
    HEADER_REGEX_ALT = re.compile(
        rf"^(?:#+\s+)?{_PORT}/{_PROTO}\s+{_SEV}",
        re.IGNORECASE,
    )
    
    # Lines worth carrying alongside the header — typically the severity+CVSS
    # line that the LLM needs to populate the cvss field for the first NVT.
    _CVSS_LINE_RE = re.compile(
        rf"^(?:#+\s+)?(?:Critical|High|Medium|Low|Log)\s*\(CVSS:\s*[0-9.]+\s*\)",
        re.IGNORECASE,
    )

    def extract_visual_context(self, visual_layout_path: str) -> Tuple[List, None, None, None]:
        """Extract the **last header + its CVSS context** from the visual layout.

        Returns a 4-tuple ``(context_lines, severity, port, protocol)``:

        * ``context_lines``: 1-2 lines — the matched header (``High 25/tcp``)
          plus the immediately following ``High (CVSS: X.X)`` line **when
          present**. The CVSS line carries the score for the first NVT after
          the header; dropping it would force the LLM to invent a cvss for
          that NVT (the very bug the cleanup of the orange "default by
          severity" rule was meant to prevent).
        * Severity / port / protocol: parsed from the header for callers that
          want the structured tuple.

        Lines unrelated to the header (Summary, page numbers, NVT bodies) are
        *not* included — that was the noise the previous implementation
        prepended to block_1.
        """
        if not visual_layout_path or 'openvas' not in visual_layout_path.lower():
            return [], None, None, None

        initial_severity = initial_port = initial_protocol = None
        header_idx = None
        layout_lines = []

        try:
            with open(visual_layout_path, encoding="utf-8") as f:
                layout_lines = [l.strip() for l in f.readlines() if l.strip()]
            for idx in range(len(layout_lines) - 1, -1, -1):
                line = layout_lines[idx]
                m = self.HEADER_REGEX.match(line) or self.HEADER_REGEX_ALT.match(line)
                if m:
                    initial_severity = m.group("sev")
                    initial_port = m.group("port")
                    initial_protocol = m.group("proto")
                    header_idx = idx
                    break
        except Exception:
            pass

        if header_idx is None:
            return [], initial_severity, initial_port, initial_protocol

        header_line = f"{initial_severity} {initial_port}/{initial_protocol}"
        context_lines = [header_line]

        # Capture up to the next 2 lines after the header IF they look like
        # a CVSS info line ("High (CVSS: 7.5)") — the LLM needs that for the
        # first NVT in the chunk. Stop at NVT: or any non-CVSS noise.
        for next_line in layout_lines[header_idx + 1: header_idx + 3]:
            if next_line.lower().startswith("nvt:"):
                break
            if self._CVSS_LINE_RE.match(next_line):
                context_lines.append(next_line)
                break  # one CVSS line is enough; further lines are noise

        return context_lines, initial_severity, initial_port, initial_protocol
    
    def create_blocks(self, report_text: str, temp_dir: str, initial_context: Tuple, output_ext: str = "txt") -> List[Dict]:
        """Parse OpenVAS report and create blocks for each vulnerability.

        Args:
            report_text: Text extracted from report (may contain markdown)
            temp_dir: Directory to save block files
            initial_context: Tuple from extract_visual_context()
            output_ext: Extension to use for block files (e.g. "txt", "md")
        """
        initial_context_lines, initial_severity, initial_port, initial_protocol = initial_context

        file_ext = f".{output_ext}"

        lines = report_text.splitlines()
        blocks = []
        current_block = []
        current_port = initial_port
        current_protocol = initial_protocol
        current_severity = initial_severity
        block_idx = 0

        # Decide ONCE whether the first block actually needs the visual-layout
        # context prepended. If the report_text already carries a header above
        # its first NVT, the LLM has all it needs — prepending becomes noise.
        # If it doesn't, the visual_layout is the only way to recover the
        # implicit "this NVT belongs to header X" — fall back to it.
        first_nvt_idx = next((i for i, l in enumerate(lines) if l.strip().startswith('NVT:')), None)
        report_has_inline_header = False
        if first_nvt_idx is not None:
            # Search the few lines above the first NVT for a header.
            window = [lines[i].strip() for i in range(max(0, first_nvt_idx - 3), first_nvt_idx)]
            for candidate in window:
                if self.HEADER_REGEX.match(candidate) or self.HEADER_REGEX_ALT.match(candidate):
                    report_has_inline_header = True
                    break
        # Skip the visual-layout prepend when the report already self-describes.
        prepend_layout = (not report_has_inline_header) and bool(initial_context_lines)

        # Try to extract port/protocol from first NVT
        if first_nvt_idx is not None and first_nvt_idx >= 2:
            port_line = lines[first_nvt_idx - 2].strip()
            port_match = self.HEADER_REGEX.match(port_line) or self.HEADER_REGEX_ALT.match(port_line)
            if port_match:
                current_severity = port_match.group("sev")
                current_port = port_match.group("port")
                current_protocol = port_match.group("proto")
            else:
                alt_match = re.match(r"^(\d+|general)/([a-zA-Z0-9_-]+)", port_line, re.IGNORECASE)
                if alt_match:
                    current_port = alt_match.group(1)
                    current_protocol = alt_match.group(2)
        
        # Iterate through lines and create blocks by severity headers
        for line in lines:
            stripped = line.strip()
            header_match = self.HEADER_REGEX.match(stripped) or self.HEADER_REGEX_ALT.match(stripped)
            if header_match:
                if current_block:
                    bloco_severity = current_severity
                    bloco_port = current_port
                    bloco_protocol = current_protocol
                    block_idx += 1
                    block_path = os.path.join(temp_dir, f"block_{bloco_severity}_{bloco_port}_{bloco_protocol}_{block_idx}{file_ext}")
                    with open(block_path, 'w', encoding='utf-8') as f:
                        if len(blocks) == 0 and prepend_layout:
                            for ctx_line in initial_context_lines:
                                f.write(f"{ctx_line}\n")
                            f.write("---\n")
                        f.write('\n'.join(current_block))
                    blocks.append({
                        'file': block_path,
                        'port': bloco_port,
                        'protocol': bloco_protocol,
                        'severity': bloco_severity
                    })
                    current_block = []
                current_severity = header_match.group("sev")
                current_port = header_match.group("port")
                current_protocol = header_match.group("proto")
            current_block.append(line)
        
        # Handle last block
        if current_block:
            block_idx += 1
            bloco_is_first = (len(blocks) == 0)
            bloco_port = current_port
            bloco_protocol = current_protocol
            bloco_severity = current_severity
            
            if bloco_is_first:
                if bloco_port is None and initial_port is not None:
                    bloco_port = initial_port
                if bloco_protocol is None and initial_protocol is not None:
                    bloco_protocol = initial_protocol
                if bloco_severity is None and initial_severity is not None:
                    bloco_severity = initial_severity
            
            block_path = os.path.join(temp_dir, f"block_{bloco_severity}_{bloco_port}_{bloco_protocol}_{block_idx}{file_ext}")
            with open(block_path, 'w', encoding='utf-8') as f:
                if bloco_is_first and prepend_layout:
                    for ctx_line in initial_context_lines:
                        f.write(f"{ctx_line}\n")
                    f.write("---\n")
                f.write('\n'.join(current_block))
            blocks.append({
                'file': block_path,
                'port': bloco_port,
                'protocol': bloco_protocol,
                'severity': bloco_severity
            })
        
        return blocks
    
    @staticmethod
    def _normalize_name(name) -> str:
        """Lowercase + strip + collapse internal whitespace for dedup key."""
        if not name:
            return ''
        return re.sub(r'\s+', ' ', str(name).strip().lower())

    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        """
        Consolida todas as vulnerabilidades do OpenVAS agrupando por (Name, port, protocol),
        faz merge das duplicatas, mantendo a mais completa (com descrição válida).
        Passa também por um dedup fuzzy (rapidfuzz) para agrupar Nomes com pequenas variações.
        """
        if not vulns:
            return []
        from collections import defaultdict
        grouped = defaultdict(list)
        for v in vulns:
            name = (v.get('Name') or '').strip()
            port = v.get('port')
            protocol = v.get('protocol')
            if name == 'Services':
                key = tuple(sorted((k, make_hashable(vv)) for k, vv in v.items()))
            else:
                key = (self._normalize_name(name), make_hashable(port), make_hashable(protocol))
            grouped[key].append(v)
        def count_filled_fields(vuln):
            # cvss=0.0 is a legitimate value for LOG-severity OpenVAS entries, so 0 is not treated as empty.
            return sum(1 for k, val in vuln.items() if val not in [None, '', [], {}])
        merged = []
        for group in grouped.values():
            if len(group) == 1:
                merged.append(group[0])
            else:
                # Merge: keep the most complete
                most_complete = max(group, key=count_filled_fields)
                merged.append(most_complete)
        return self._fuzzy_merge(merged, threshold=90)

    _CVE_PATTERN = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

    def _extract_cves(self, vuln: Dict) -> set:
        """
        Extract CVE IDs from `references` field (typically a list of strings).
        Used as semantic guard in fuzzy merge: vulns with disjoint CVE sets are
        treated as distinct even when names are similar.
        """
        cves = set()
        refs = vuln.get('references')
        if not refs:
            return cves
        if isinstance(refs, list):
            for r in refs:
                cves.update(m.upper() for m in self._CVE_PATTERN.findall(str(r)))
        else:
            cves.update(m.upper() for m in self._CVE_PATTERN.findall(str(refs)))
        return cves

    def _should_merge(self, v: Dict, cluster_rep: Dict, threshold: int, fuzz) -> bool:
        """
        Decide whether vuln `v` should join the cluster represented by `cluster_rep`.

        Step 1 — Name similarity gate: fuzz.ratio < threshold rejects immediately.
        Step 2 — CVE semantic guard: when both vulns carry CVEs, merge only when
                 one CVE set is a subset of the other (one extraction missed CVEs
                 the other captured). Partial overlap with extras on both sides
                 means the vulns are actually distinct (e.g. shared CVE-A but
                 each carries a unique CVE-B/CVE-C). When either side has no CVE,
                 falls back to the threshold decision.
        """
        vname = self._normalize_name(v.get('Name') or '')
        rep_name = self._normalize_name(cluster_rep.get('Name') or '')
        if not (vname and rep_name):
            return False
        if fuzz.ratio(vname, rep_name) < threshold:
            return False

        v_cves = self._extract_cves(v)
        rep_cves = self._extract_cves(cluster_rep)
        if v_cves and rep_cves and not (v_cves.issubset(rep_cves) or rep_cves.issubset(v_cves)):
            return False
        return True

    def _fuzzy_merge(self, vulns: List[Dict], threshold: int = 90) -> List[Dict]:
        """
        Second dedup pass: within same (port, protocol), cluster vulns whose
        normalized Name similarity >= threshold (via rapidfuzz) AND whose CVE
        sets are not disjoint. Keeps the most complete in each cluster.
        'Services' entries are passed through unchanged.
        """
        if not vulns:
            return []
        try:
            from rapidfuzz import fuzz
        except ImportError:
            return vulns
        from collections import defaultdict
        buckets = defaultdict(list)
        services = []
        for v in vulns:
            if (v.get('Name') or '').strip() == 'Services':
                services.append(v)
            else:
                buckets[(make_hashable(v.get('port')), make_hashable(v.get('protocol')))].append(v)

        def count_filled_fields(vuln):
            # cvss=0.0 is a legitimate value for LOG-severity OpenVAS entries, so 0 is not treated as empty.
            return sum(1 for k, val in vuln.items() if val not in [None, '', [], {}])

        result = list(services)
        for items in buckets.values():
            if len(items) == 1:
                result.append(items[0])
                continue
            # Greedy clustering: name similarity gate, then CVE semantic guard
            clusters: List[List[Dict]] = []
            for v in items:
                placed = False
                for cluster in clusters:
                    if self._should_merge(v, cluster[0], threshold, fuzz):
                        cluster.append(v)
                        placed = True
                        break
                if not placed:
                    clusters.append([v])
            for cluster in clusters:
                if len(cluster) == 1:
                    result.append(cluster[0])
                else:
                    result.append(max(cluster, key=count_filled_fields))
        return result
    
    def get_consolidation_report(self, input_count: int, output_count: int, removed: int) -> Dict:
        """
        Retorna report específico da estratégia OpenVAS.
        """
        return {
            'strategy_name': 'OpenVAS custom merge',
            'description': 'Groups vulnerabilities by (Name, port, protocol), keeps most complete',
            'input_count': input_count,
            'output_count': output_count,
            'removed': removed,
            'reason': 'duplicate merge',
            'note': 'This is the custom OpenVAS consolidation strategy'
        }
