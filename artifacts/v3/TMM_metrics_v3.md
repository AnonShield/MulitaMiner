# MulitaMiner — Metrics Report

**Generated:** 2026-07-19 07:27:28  
**Baseline:** `baselines/native/vulnnet_scans_openvas.csv`  
**Versions:** 5

---

## 1. Methodology Overview

Each LLM-generated CSV is matched against the OpenVAS baseline via an **inner join**
on `Name` (LLM CSV) = `NVT Name` (baseline). All rows from both files are used — no
deduplication — so that every scan instance is individually evaluated against every
matching baseline entry. Only matched pairs are scored.

---

## 2. Semantic Fields

Fields whose content is free text and evaluated with similarity metrics:

| Field | Baseline Column |
|---|---|
| `description` | Summary |
| `detection_result` | Specific Result |
| `detection_method` | Vulnerability Detection Method |
| `product_detection_result` | Product Detection Result |
| `impact` | Impact |
| `solution` | Solution |
| `insight` | Vulnerability Insight |

### 2.1 Metrics Applied to Each Semantic Field

| Metric | Description |
|---|---|
| **ROUGE-L** | Longest Common Subsequence F-measure between hypothesis and reference. Range [0, 1]. |
| **Token-F1** | Precision × Recall over token sets (bag-of-words). Range [0, 1]. |
| **TF-IDF Cosine** | Cosine similarity between TF-IDF vectors of hypothesis and reference. Range [0, 1]. |
| **Soft-F1 (BERTScore proxy)** | Word-level TF-IDF soft alignment: for each token in hypothesis find closest token in reference via cosine similarity. Computes Precision (P), Recall (R), and F1. Approximates BERTScore without requiring a neural model. Range [0, 1]. |

**Main Score** reported in Summary: ROUGE-L mean.

**Quality thresholds:** >= 0.70 Highly Similar | 0.60–0.70 Moderately Similar | 0.40–0.60 Slightly Similar | < 0.40 Divergent | Absent

---

## 3. References Field (CVE IDs)

`references` maps to the `CVEs` column in the baseline.

| Metric | Description |
|---|---|
| **Set-F1** | Precision and Recall computed over sets of CVE identifiers extracted from each text. F1 = harmonic mean. |

---

## 4. Deterministic Fields

Fields with a fixed controlled vocabulary or numeric value:

| Field | Baseline Column | Metric |
|---|---|---|
| `cvss` | CVSS | Exact Match |
| `port` | Port | Exact Match (float→int normalised) |
| `protocol` | Port Protocol | Exact Match |
| `severity` | Severity | F1-macro (multi-class) |

**Exact Match:** proportion of pairs where the predicted value equals the reference exactly.

**F1-macro for Severity:** each severity level (LOG / LOW / MEDIUM / HIGH / CRITICAL) is
treated as a class. Precision, Recall, and F1 are computed per class then macro-averaged.

---

## 5. Omission & Hallucination

| Symbol | Condition | Meaning |
|---|---|---|
| **OK** | Both filled | LLM and baseline both have a value |
| **O** (Omission) | LLM empty, baseline filled | LLM failed to produce content for a field that exists in the baseline |
| **A** (Hallucination) | LLM filled, baseline empty | LLM invented content for a field that is empty in the baseline |
| **N/A** | Both empty | Field not applicable for this vulnerability |

Rate = count / total matched pairs × 100 %.

---

## 6. Field Mapping: LLM vs Baseline

The table below shows how each field in the LLM CSV is mapped to the corresponding
column in the OpenVAS baseline CSV, and which fields exist only in one source.

### 6.1 Mapped Fields (LLM ↔ Baseline)

| LLM Field | Baseline Column | Metric Type |
|---|---|---|
| `description` | Summary | Semantic (ROUGE-L, Token-F1, TF-IDF, Soft-F1) |
| `detection_result` | Specific Result | Semantic |
| `detection_method` | Vulnerability Detection Method | Semantic |
| `product_detection_result` | Product Detection Result | Semantic |
| `impact` | Impact | Semantic |
| `solution` | Solution | Semantic |
| `insight` | Vulnerability Insight | Semantic |
| `references` | CVEs | Set-F1 (CVE identifiers) |
| `cvss` | CVSS | Exact Match |
| `port` | Port | Exact Match (numeric) |
| `protocol` | Port Protocol | Exact Match |
| `severity` | Severity | F1-macro (multi-class) |

### 6.2 LLM-Only Fields (no baseline counterpart)

| LLM Field | Description |
|---|---|
| `log_method` | Logging method used by the LLM during extraction |
| `plugin` | Plugin identifier used in extraction |
| `identification` | Identification details extracted by LLM |
| `http_info` | HTTP-specific information extracted by LLM |
| `source` | Source of the vulnerability data |
| `llm` | LLM model identifier used for extraction |
| `target` | Target host information |

### 6.3 Baseline-Only Columns (not in LLM CSV)

| Baseline Column | Description |
|---|---|
| IP | Host IP address |
| Hostname | Host FQDN or alias |
| QoD | Quality of Detection score |
| Solution Type | Type of solution (Mitigation / VendorFix / etc.) |
| NVT OID | OpenVAS NVT Object Identifier |
| Task ID | Scan task identifier |
| Task Name | Scan task name |
| Timestamp | Scan result timestamp |
| Result ID | Unique result identifier |
| Affected Software/OS | Affected software or OS version |
| BIDs | Bugtraq IDs |
| CERTs | CERT advisories |
| Other References | Additional vulnerability references |
| NVT Name | Vulnerability name (join key) |

---

## 7. Results Summary

### DEEPSEEK

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv3 | 0.9347 | 0.9795 | 0.7068 | 0.5966 | 0.3289 | 0.6358 | 0.6576 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv3 | 0.9998 | 0.9791 | 0.9977 | 1.0000 | 0.9639 |

---

### GPT4

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv3 | 0.9870 | 0.9792 | 0.4415 | 0.5737 | 0.3407 | 0.6912 | 0.5806 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv3 | 0.9993 | 0.9777 | 0.9975 | 0.9995 | 0.9528 |

---

### GPT5

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv3 | 0.9320 | 0.9620 | 0.6852 | 0.4394 | 0.3252 | 0.6415 | 0.6485 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv3 | 0.9998 | 0.9791 | 0.9977 | 1.0000 | 0.9541 |

---

### LLAMA3

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv3 | 0.9698 | 0.9469 | 0.4624 | 0.5834 | 0.3299 | 0.7077 | 0.6424 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv3 | 0.9996 | 0.9771 | 0.9977 | 0.9996 | 0.9185 |

---

### LLAMA4

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv3 | 0.9678 | 0.9403 | 0.5062 | 0.5085 | 0.3299 | 0.6927 | 0.6350 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv3 | 0.9981 | 0.9779 | 0.9972 | 0.9989 | 0.9307 |

---
