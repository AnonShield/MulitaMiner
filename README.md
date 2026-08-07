<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="imgs/MulitaMiner_logo_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="imgs/MulitaMiner_logo_light.png">
    <img src="imgs/MulitaMiner_logo_light.png" width="420" alt="MulitaMiner logo">
  </picture>

**Vulnerability Extraction from Security Reports using LLMs**

</div>

---

# Artifact Index

> ⚠️ **This branch (`main`) is not an evaluation artifact.** It is an index. The
> repository hosts the artifacts of two different papers, each one on its own branch.

| Paper | Artifact branch | Frozen tag |
| ----- | --------------- | ---------- |
| **SBSeg 2026 · Main Track**<br>*MulitaMiner: A Multi-Version Evaluation of LLM-Based Vulnerability Report Extraction*<br><sub>Pipeline progression V1 → V2 → V3, evaluated with **cloud LLMs** across 450 runs.</sub> | **[▶ `V3`](../../tree/V3)** | [`sbseg2026-artifact`](../../tree/sbseg2026-artifact) |
| **WTICG 2026**<br>*On-Premise vs. Cloud: Local LLMs for Vulnerability Extraction from Security Scanner Reports*<br><sub>Nine **local models** (4B to 21B) compared against a DeepSeek cloud reference.</sub> | **[▶ `slms`](../../tree/slms)** | [`wticg2026-artifact`](../../tree/wticg2026-artifact) |

Both papers deal with LLM-based vulnerability extraction, but they are distinct works:
the **SBSeg** one measures how far **pipeline engineering** carries extraction quality
using cloud models, while the **WTICG** one measures the quality cost of running **local
models** to keep scanner reports confidential. Check the title before starting the review.

Every artifact branch carries its own complete `README.md`, with considered badges, basic
information, dependencies, installation, minimum test and the claims of its paper.

## Branch or tag?

The **branch** always holds the latest state of an artifact. The **tag** is frozen: it
points at the exact commit submitted for evaluation and never moves, so the code under
review cannot shift while you are reviewing it. Either link works, and both render the
same README.

## Previous material

| Content | Reference |
| ------- | --------- |
| Artifact of the previous version of the tool (dataset of 6,700 vulnerabilities extracted from 129 OpenVAS reports), archived on Zenodo | [`v2-dataset-artifact`](../../tree/v2-dataset-artifact) |

That tag preserves the state of this branch from before it became an index, so already
published references remain valid.

## About the tool

**MulitaMiner** is an automated tool for extracting and structuring vulnerabilities from
heterogeneous PDF reports produced by security scanners (OpenVAS, Tenable WAS). Its
LLM-based pipeline combines scanner-aware adaptive segmentation and specialized prompting
to turn unstructured findings into consistent, analysis-ready records, with standardized
outputs and quality validation.

## LICENSE

Distributed under the MIT License. See [LICENSE](LICENSE).
