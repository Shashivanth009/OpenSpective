# OpenSpective AI Architecture & Evidence Grounding

## 1. AI Integration Overview

OpenSpective uses hosted serverless inference via **Cloudflare Workers AI**. The AI layer is strictly an explanatory and synthesizing assistant—it never invents findings, never conducts primary data collection, and is completely optional. If Workers AI is unavailable or quotas are exceeded, all core reconnaissance, graphing, and export features function without interruption.

---

## 2. Model Selection & Configuration

- **Active Model:** `@cf/meta/llama-3.1-8b-instruct`
- **Hosting Location:** Cloudflare global edge network (zero external API keys or third-party data transmission required).
- **Execution Parameter:**
  - `max_tokens`: 800
  - `temperature`: 0.1 (low temperature for deterministic, factual outputs)
- **Token Input Guardrails:** Input evidence is capped at the 50 highest-confidence findings to prevent context overflow and minimize inference latency.

---

## 3. Strict Evidence Grounding Protocol

The prompt template enforced in `apps/worker/src/routes/investigations.ts` applies mandatory guardrails:

```markdown
You are an OSINT analyst reviewing findings for an investigation.

Target: <normalized_target> (type: <target_type>)

Findings:
[category/type] value (notes) — source: <source>, confidence: <confidence>

Provide:
1. Executive summary (2-3 sentences).
2. Key technical findings and significance.
3. Notable gaps or limitations.
4. Actionable defensive recommendations.
5. Confidence assessment.

Rules:
- Only reference the actual findings listed above.
- Do not invent data, CVEs, or claims not supported by findings.
- Clearly distinguish observed facts from inferences.
- If findings are sparse, say so honestly.
```

---

## 4. Quota Accounting & Cost Control

1. **Per-Account Limits:** Capped at 20 AI analyses per user per calendar month.
2. **Persistence & Caching:** Each analysis is saved permanently in the D1 `ai_analyses` table and linked to `investigations.ai_analysis_id`. Repeated views of the same investigation do not trigger new inference calls.
3. **Usage Tracking:** Every invocation increments `usage_records.ai_inference_count` in D1 for the active monthly billing period.
