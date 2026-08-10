# MulitaMiner — Metrics Report

**Generated:** 2026-07-19 07:27:26  
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
| TMMv2 | 0.8755 | 0.9696 | 0.6702 | 0.6013 | 0.3150 | 0.6278 | 0.5988 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv2 | 0.7961 | 0.9781 | 0.9968 | 0.9301 | 0.8877 |

---

### GPT4

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv2 | 0.9587 | 0.9309 | 0.3820 | 0.4908 | 0.3150 | 0.6880 | 0.3918 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv2 | 0.7767 | 0.9729 | 0.9961 | 0.9326 | 0.8413 |

---

### GPT5

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv2 | 0.8937 | 0.9392 | 0.6820 | 0.5204 | 0.3578 | 0.6563 | 0.6019 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv2 | 0.7843 | 0.9779 | 0.9972 | 0.9559 | 0.8449 |

---

### LLAMA3

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv2 | 0.9249 | 0.9234 | 0.4073 | 0.5416 | 0.3127 | 0.6661 | 0.5548 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv2 | 0.8312 | 0.9765 | 0.9971 | 0.9664 | 0.8582 |

---

### LLAMA4

**Semantic — ROUGE-L mean**

| Version | description | detection_result | detection_method | product_detection_result | impact | solution | insight |
|---|---|---|---|---|---|---|---|
| TMMv2 | 0.9302 | 0.8720 | 0.3188 | 0.4834 | 0.3105 | 0.6894 | 0.5492 |

**Deterministic scores**

| Version | CVSS EM | Port EM | Protocol EM | Severity F1 | CVE Set-F1 |
|---|---|---|---|---|---|
| TMMv2 | 0.8431 | 0.9755 | 0.9969 | 0.9718 | 0.8697 |

---
