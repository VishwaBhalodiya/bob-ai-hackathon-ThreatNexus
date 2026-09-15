"""
AI-assisted threat explainer.

Uses IBM watsonx.ai (Granite model) to generate a plain-English explanation
of why an alert is dangerous and what the analyst should investigate next.

Falls back to a deterministic template-based explanation when the
watsonx.ai credentials are not configured (safe for demo / offline use).
"""

import os
import textwrap
from typing import List, Tuple

# ─── Optional IBM watsonx.ai client ───────────────────────────────────────────

try:
    from ibm_watsonx_ai import Credentials
    from ibm_watsonx_ai.foundation_models import ModelInference

    _WATSONX_AVAILABLE = True
except ImportError:
    _WATSONX_AVAILABLE = False

WATSONX_API_KEY = os.getenv("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
WATSONX_URL = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
WATSONX_MODEL = os.getenv("WATSONX_MODEL_ID", "ibm/granite-3-8b-instruct")


def _build_prompt(
    title: str,
    description: str,
    iocs: List[dict],
    risk_score: float,
    risk_level: str,
    asset_hostname: str,
    asset_criticality: int,
    threat_categories: List[str],
    score_components: dict,
) -> str:
    ioc_summary = ", ".join(f"{i['type']}:{i['value']}" for i in iocs[:6]) or "none identified"
    cat_summary = ", ".join(threat_categories) if threat_categories else "unknown"
    components = score_components.get("components", {})

    return textwrap.dedent(f"""
        You are a senior cybersecurity analyst. Analyse the following security alert and
        provide a clear, actionable explanation suitable for a Security Operations Centre (SOC) analyst.

        ## Alert Details
        - Title: {title}
        - Description: {description or 'N/A'}
        - Risk Score: {risk_score}/100 ({risk_level})
        - Affected Asset: {asset_hostname} (criticality {asset_criticality}/10)
        - Indicators of Compromise: {ioc_summary}
        - Threat Categories: {cat_summary}
        - Score Breakdown: source_severity={components.get('source_severity', 0):.1f},
          ioc_reputation={components.get('ioc_reputation', 0):.1f},
          asset_criticality={components.get('asset_criticality', 0):.1f},
          behaviour={components.get('behaviour', 0):.1f},
          correlation={components.get('correlation', 0):.1f}

        ## Your Task
        1. Explain in 2-3 sentences WHY this alert is {risk_level} risk.
        2. List exactly 4 concrete investigation steps the analyst should take, numbered 1-4.
        3. Keep the tone professional, concise, and actionable.

        Respond in this exact format:
        EXPLANATION: <your 2-3 sentence explanation>
        STEPS:
        1. <step>
        2. <step>
        3. <step>
        4. <step>
    """).strip()


def _parse_response(text: str) -> Tuple[str, List[str]]:
    """Parse the structured LLM response into explanation + steps list."""
    explanation = ""
    steps: List[str] = []

    lines = text.strip().splitlines()
    in_steps = False

    for line in lines:
        line = line.strip()
        if line.startswith("EXPLANATION:"):
            explanation = line[len("EXPLANATION:"):].strip()
        elif line.startswith("STEPS:"):
            in_steps = True
        elif in_steps and line and line[0].isdigit() and "." in line[:3]:
            steps.append(line.split(".", 1)[1].strip())

    if not explanation:
        explanation = text[:300]
    if not steps:
        steps = ["Review the raw log data for additional context.",
                 "Check threat intelligence feeds for the identified IOCs.",
                 "Verify asset posture and recent changes.",
                 "Escalate to Tier 2 if the threat cannot be dismissed."]

    return explanation, steps[:4]


def _template_explanation(
    title: str,
    risk_level: str,
    risk_score: float,
    iocs: List[dict],
    asset_hostname: str,
    asset_criticality: int,
    threat_categories: List[str],
) -> Tuple[str, List[str]]:
    """Deterministic fallback when watsonx.ai is unavailable."""
    cat_str = ", ".join(threat_categories) if threat_categories else "suspicious activity"
    ioc_types = list({i["type"] for i in iocs})
    ioc_str = " and ".join(ioc_types) if ioc_types else "indicators"

    explanation = (
        f"This {risk_level.lower()}-risk alert (score {risk_score:.0f}/100) was triggered on "
        f"{asset_hostname} (criticality {asset_criticality}/10) and involves {ioc_str} "
        f"associated with {cat_str}. "
        f"The risk score reflects the combination of source severity, IOC reputation, and asset value."
    )

    steps = [
        f"Isolate or closely monitor {asset_hostname} to prevent lateral movement.",
        f"Query threat intelligence feeds for all extracted IOCs: {', '.join(i['value'] for i in iocs[:3])}.",
        "Review firewall and proxy logs for outbound connections to identified IPs/domains.",
        "Collect memory and process artefacts from the affected host for forensic analysis.",
    ]
    return explanation, steps


def generate_explanation(
    title: str,
    description: str,
    iocs: List[dict],
    risk_score: float,
    risk_level: str,
    asset_hostname: str = "unknown",
    asset_criticality: int = 5,
    threat_categories: List[str] = None,
    score_components: dict = None,
) -> Tuple[str, List[str]]:
    """
    Generate a plain-English explanation and investigation steps for an alert.

    Returns ``(explanation_text, [step1, step2, step3, step4])``.
    Tries watsonx.ai first; falls back to template if credentials are absent.
    """
    threat_categories = threat_categories or []
    score_components = score_components or {}

    # ── watsonx.ai path ────────────────────────────────────────────────────────
    if _WATSONX_AVAILABLE and WATSONX_API_KEY and WATSONX_PROJECT_ID:
        try:
            credentials = Credentials(api_key=WATSONX_API_KEY, url=WATSONX_URL)
            model = ModelInference(
                model_id=WATSONX_MODEL,
                credentials=credentials,
                project_id=WATSONX_PROJECT_ID,
                params={
                    "max_new_tokens": 400,
                    "temperature": 0.3,
                    "repetition_penalty": 1.1,
                },
            )
            prompt = _build_prompt(
                title, description, iocs, risk_score, risk_level,
                asset_hostname, asset_criticality, threat_categories, score_components,
            )
            response = model.generate_text(prompt=prompt)
            return _parse_response(response)
        except Exception:
            pass  # Fall through to template

    # ── Template fallback ──────────────────────────────────────────────────────
    return _template_explanation(
        title, risk_level, risk_score, iocs, asset_hostname,
        asset_criticality, threat_categories,
    )
