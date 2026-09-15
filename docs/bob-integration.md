# IBM Bob Integration

IBM Bob is the only AI provider in ThreatNexus. It is used in two ways.

## 1. Bob generates every BLUF summary (load-bearing at runtime)

`src/backend/services/ai_engine.py` is the single point where model output enters the product.

### What Bob is asked

For each alert the pipeline builds a structured prompt (`_build_prompt`) containing everything
the engines computed — not the raw log:

```
Alert details:
- Source IP:          45.155.204.18
- Event type:         Command & Control
- Severity:           CRITICAL
- Risk score:         98.3/100  (CRITICAL priority)
- IOC reputation:     96/100  (confidence: 94%)
- Threat type:        Command & Control
- Target asset:       DC01.corp.local  (criticality: CRITICAL)
- Correlation score:  60/100  (related alerts in last 24h)
- MITRE ATT&CK technique: T1071 – Application Layer Protocol (tactic: Command & Control).
- Correlation verdict: Genuine Threat
- Verdict signals:    Source matches a known-malicious indicator (96/100); Part of a multi-stage
                      attack chain spanning 3+ MITRE tactics; Targets a CRITICAL-criticality asset
```

and a system message that enforces the BLUF discipline (verdict and action first, JSON only).
Bob must return exactly:

```json
{
  "bottom_line":    "CRITICAL — genuine threat; isolate DC01.corp.local now …",
  "situation":      "…",
  "assessment":     "…",
  "recommendation": "…"
}
```

### The call

```
POST {BOB_BASE_URL}/v1/chat/completions
Authorization: Bearer {BOB_API_KEY}
X-Team-ID: {BOB_TEAM_ID}            # only for General keys
{ "model": BOB_MODEL, "messages": [system, user], "max_tokens": 400, "temperature": 0.3 }
```

The response is stripped of any markdown fences, parsed as JSON and validated for the four keys
(`_parse_bluf`). Temperature 0.3 keeps output factual and repeatable.

### The contract with the rest of the system

* **Bounded latency.** `BOB_TIMEOUT` (default 3 s). A detail page never hangs on the model.
* **Identical fallback shape.** On timeout, HTTP error, bad JSON or missing keys the deterministic
  template (`_template_explanation`) renders the same four fields from the same inputs. The UI,
  the brief and the API are unaware which path produced the text.
* **Bulk safety.** The Commander Brief generates one BLUF per ranked item; it uses templates by
  default and opts into Bob with `GET /api/brief?llm=true`, so one page view cannot fan out into
  dozens of unbounded model calls.
* **Observability.** `GET /api/ai/status` reports `provider`, `mode` (`bob` | `template`),
  `model`, `configured`, and live counters (`bob_calls`, `bob_failures`, `template_fallbacks`,
  `last_error`). The `AiEngineBadge` in the dashboard and brief headers polls it every 15 s so a
  judge can see at a glance whether Bob is live.

### Where Bob's output surfaces

| Surface | Field |
|---|---|
| Alert Detail → *AI Analysis* | bottom line · situation · assessment |
| Alert Detail → *Recommended Actions* | recommendation, split into steps |
| Commander Brief → *Prioritised investigations* | one four-part BLUF per ranked threat |
| `POST /api/analyze` | ad-hoc assessment of an event without persisting |

## 2. Bob built the solution (development)

The IBM Bob coding agent was used throughout development: scaffolding the FastAPI/React
structure, generating the CEF/syslog/STIX parsers and their test fixtures, writing the
false-positive classifier's explanation strings, and producing the sample feeds in
`src/backend/sample_feeds/` from format specifications.

## Configuration

```
src/backend/.env          (copy from src/.env.example)
BOB_ENABLED=true
BOB_API_KEY=…
BOB_BASE_URL=https://<bob-host>/api
BOB_MODEL=<model id on your instance>
BOB_TIMEOUT=3
BOB_TEAM_ID=              # General keys only
```

Without these, ThreatNexus runs in template mode and says so in the UI — it never silently
pretends the text came from a model.
