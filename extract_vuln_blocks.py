import re
import os
from collections import defaultdict

# Configurações
INPUT_TXT = "OpenVAS_JuiceShop.txt"  # Alterar
OUTPUT_DIR = "vuln_blocks"


# Regex para identificar início de vulnerabilidade (OpenVAS):
VULN_HEADER = re.compile(r"^\s*(?:High|Medium|Low|Log|Critical)\s+\d+/\w+|^\s*NVT:", re.IGNORECASE)

# Cria pasta de saída
os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(INPUT_TXT, encoding="utf-8") as f:
    lines = f.readlines()

blocks = defaultdict(list)
current_name = None
current_block = []

for line in lines:
    if VULN_HEADER.match(line.strip()):
        # Salva bloco anterior
        if current_name and current_block:
            blocks[current_name].append(current_block)
        # Inicia novo bloco
        current_name = line.strip()
        current_block = [line]
    elif current_name:
        current_block.append(line)

# Salva último bloco
if current_name and current_block:
    blocks[current_name].append(current_block)

# Escreve arquivos separados
for name, occurrences in blocks.items():
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)[:40]
    for idx, block in enumerate(occurrences, 1):
        out_path = os.path.join(OUTPUT_DIR, f"{safe_name}_{idx}.txt")
        with open(out_path, "w", encoding="utf-8") as out:
            out.writelines(block)

print(f"Extração concluída! {sum(len(v) for v in blocks.values())} blocos salvos em '{OUTPUT_DIR}'")
