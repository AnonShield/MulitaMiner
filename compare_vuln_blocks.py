import os
import difflib
import re
from collections import defaultdict

BLOCKS_DIR = "vuln_blocks"
REPORT_FILE = "duplicatas_relatorio.txt"

# Agrupa arquivos por prefixo (ignorando _1, _2, ...)
def group_by_prefix(files):
    groups = defaultdict(list)
    for fname in files:
        prefix = re.sub(r"_\d+\.txt$", "", fname)
        groups[prefix].append(fname)
    return groups

def compare_files(file1, file2):
    with open(os.path.join(BLOCKS_DIR, file1), encoding="utf-8") as f1, \
         open(os.path.join(BLOCKS_DIR, file2), encoding="utf-8") as f2:
        lines1 = [l.strip() for l in f1.readlines() if l.strip()]
        lines2 = [l.strip() for l in f2.readlines() if l.strip()]
    diff = list(difflib.unified_diff(lines1, lines2, lineterm=""))
    return diff

def main():
    files = [f for f in os.listdir(BLOCKS_DIR) if f.endswith(".txt")]
    groups = group_by_prefix(files)
    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        for prefix, flist in groups.items():
            if len(flist) > 1:
                report.write(f"==== {prefix} === (total: {len(flist)})\n")
                for i in range(len(flist)):
                    for j in range(i+1, len(flist)):
                        diff = compare_files(flist[i], flist[j])
                        if not diff:
                            report.write(f"  {flist[i]} == {flist[j]} (EXATAS)\n")
                        else:
                            report.write(f"  {flist[i]} != {flist[j]} (DIFERENÇAS)\n")
                            for line in diff[:10]:  # Mostra só as 10 primeiras linhas do diff
                                report.write(f"    {line}\n")
                            if len(diff) > 10:
                                report.write("    ...\n")
                report.write("\n")
    print(f"Relatório gerado em {REPORT_FILE}")

if __name__ == "__main__":
    main()
