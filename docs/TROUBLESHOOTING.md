# Troubleshooting Guide

This document covers common errors and optimization tips for MulitaMiner.

## Token Errors

| Error                                              | Cause                              | Solution                                         |
| -------------------------------------------------- | ---------------------------------- | ------------------------------------------------ |
| "Setting 'max_tokens' and 'max_completion_tokens'" | Conflict between OpenAI parameters | System fixed to use only `max_completion_tokens` |
| "Token limit exceeded"                             | Chunk too large                    | Optimized chunk system solves automatically      |
| "Rate limit exceeded"                              | Too many requests                  | Wait for quota reset or use alternative provider |

## Connectivity Errors

| Error                | Cause                   | Solution                                |
| -------------------- | ----------------------- | --------------------------------------- |
| `SSL/Network`        | Temporary network issue | Try again or increase `timeout`         |
| "Invalid API key"    | Incorrect/expired key   | Check configuration in `.env`           |
| "Discontinued model" | Model not available     | Update to valid model in configurations |

## Model Errors

| Error             | Cause                   | Solution                   |
| ----------------- | ----------------------- | -------------------------- |
| "quota limit"     | Provider limit exceeded | Use Groq or wait for reset |
| "model not found" | Incorrect name          | Check LLM configuration    |

## Optimization Tips

### By Report Size

| Size             | Recommendation | Justification                       |
| ---------------- | -------------- | ----------------------------------- |
| **< 50 pages**   | GPT-4/GPT-5    | Larger chunks, efficient processing |
| **50-200 pages** | Llama3/Qwen3   | Optimal balancing                   |
| **> 200 pages**  | Llama4         | More precise incremental processing |

### By Analysis Type

| Scenario                | Best LLM    | Why?                              |
| ----------------------- | ----------- | --------------------------------- |
| **Technical Analysis**  | DeepSeek    | Specialized in code/security      |
| **Critical Processing** | GPT-5       | Maximum security and precision    |
| **Economy**             | Llama3/Groq | Efficient                         |
| **Debugging**           | Llama4      | Maximum precision in small chunks |

## Performance Tips

- **Optimized BERTScore**: Model loaded once, evaluation in ~30 seconds
- **Evaluation with duplicates**: Use `--allow-duplicates` with OpenVAS
- **Monitoring**: Detailed logs for bottleneck identification

## Debugging Tools

### Chunk Validation

Validate chunk division before processing:

```bash
python tools/chunk_validator.py report.pdf --llm gpt4 --scanner tenable
```

This provides:

- Token distribution analysis
- Scanner pattern detection
- Chunk integrity validation
- Suggested configuration optimization
- Detailed efficiency reports

### Log Analysis

Check generated logs for debugging:

- `*_removed_log.txt`: Vulnerabilities removed due to missing fields
- `*_duplicates_removed_log.txt`: Exact duplicates removed
- `*_merge_log.txt`: Vulnerabilities merged

## Common Issues

### Empty or Incomplete Extraction

1. **Check PDF quality**: Ensure the PDF is text-based (not scanned images)
2. **Verify scanner configuration**: Use the correct `--scanner` for your report type
3. **Check chunk size**: Use `chunk_validator.py` to analyze token distribution

### API Rate Limits

1. **Use alternative providers**: Switch from OpenAI to Groq
2. **Reduce batch size**: Process fewer PDFs at a time
3. **Add delays**: Implement pauses between requests

### Memory Issues with Large PDFs

1. **Increase system RAM**: 4GB+ recommended
2. **Use smaller chunks**: Choose LLMs with smaller `max_chunk_size`
3. **Process in batches**: Split large reports into smaller files
