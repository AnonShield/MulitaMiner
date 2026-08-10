# MulitaMiner — Metrics Report

**Generated:** 2026-07-19 07:27:17  
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
| TMMv1 | 0.8889 | 0.8755 | 0.5290 | 0.5430 | 0.2593 | 0.5333 | 0.4879 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv1 | 0.8126 | 0.9673 | 0.9958 | 0.9360 | 0.7051 |

---

### GPT4

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv1 | 0.9527 | 0.8387 | 0.2951 | 0.4591 | 0.2748 | 0.6153 | 0.4677 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv1 | 0.8592 | 0.9770 | 0.9975 | 0.9463 | 0.7340 |

---

### GPT5

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv1 | 0.8409 | 0.7529 | 0.3764 | 0.5360 | 0.2582 | 0.4668 | 0.3466 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv1 | 0.7987 | 0.9882 | 1.0000 | 0.9644 | 0.4898 |

---

### LLAMA3

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv1 | 0.8907 | 0.8498 | 0.3174 | 0.5217 | 0.2692 | 0.5984 | 0.5022 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv1 | 0.8829 | 0.9750 | 0.9948 | 0.9619 | 0.8005 |

---

### LLAMA4

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv1 | 0.8791 | 0.8004 | 0.2506 | 0.4259 | 0.2632 | 0.5848 | 0.4635 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv1 | 0.8822 | 0.9778 | 0.9966 | 0.9359 | 0.6620 |

---
