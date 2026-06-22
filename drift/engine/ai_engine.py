"""AI Engine — augments deterministic analysis with LLM reasoning.

AI DOES NOT replace the rule engine. It explains, prioritizes, and summarizes.

Uses Google Gemini (google-genai) for:
1. Cross-boundary threat explanation
2. Threat prioritization
3. Mitigation suggestions
4. Threat delta summaries for PR comments

Gracefully degrades to no-op if no API key is configured.
"""

from __future__ import annotations

import json
import os
import logging
from typing import Optional

from drift.models import (
    AnalysisResult,
    Architecture,
    Threat,
    ThreatDelta,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AI Client wrapper
# ---------------------------------------------------------------------------

class AIEngine:
    """AI augmentation engine backed by Google Gemini."""

    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        self._client = None
        self._model = "gemini-2.0-flash"
        self._enabled = enabled

        if not enabled:
            logger.info("AI engine disabled by user (--no-ai)")
            return

        key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            logger.info("No AI API key found. AI augmentation disabled. "
                       "Set GEMINI_API_KEY to enable.")
            self._enabled = False
            return

        try:
            from google import genai
            self._client = genai.Client(api_key=key)
            logger.info("AI engine initialized with Google Gemini")
        except ImportError:
            logger.warning("google-genai not installed. AI augmentation disabled.")
            self._enabled = False
        except Exception as e:
            logger.warning(f"Failed to initialize AI engine: {e}")
            self._enabled = False

    @property
    def is_available(self) -> bool:
        """Check if AI engine is available and enabled."""
        return self._enabled and self._client is not None

    def enhance_threats(self, threats: list[Threat], architecture: Architecture) -> list[Threat]:
        """Enhance threats with AI-generated explanations and mitigations.

        The rule engine already generated threats with evidence.
        AI adds richer explanations and more specific mitigations.
        """
        if not self.is_available or not threats:
            return threats

        # Build architecture context for the AI
        arch_context = self._build_architecture_context(architecture)

        enhanced = []
        # Process in batches to reduce API calls
        batch_size = 10
        for i in range(0, len(threats), batch_size):
            batch = threats[i:i + batch_size]
            enhanced_batch = self._enhance_batch(batch, arch_context)
            enhanced.extend(enhanced_batch)

        return enhanced

    def prioritize_threats(self, threats: list[Threat]) -> list[Threat]:
        """Use AI to prioritize threats by production impact likelihood."""
        if not self.is_available or len(threats) <= 3:
            return threats

        prompt = self._build_prioritization_prompt(threats)
        response = self._generate(prompt)

        if response:
            return self._apply_prioritization(threats, response)
        return threats

    def summarize_delta(self, delta: ThreatDelta, architecture: Architecture) -> str:
        """Generate an AI-powered summary of architectural drift for PR comments."""
        if not self.is_available or not delta.has_changes:
            return ""

        prompt = self._build_delta_summary_prompt(delta, architecture)
        response = self._generate(prompt)
        return response or ""

    # -----------------------------------------------------------------------
    # Private methods
    # -----------------------------------------------------------------------

    def _generate(self, prompt: str) -> Optional[str]:
        """Call the Gemini API and return the response text."""
        if not self._client:
            return None

        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=prompt,
            )
            return response.text
        except Exception as e:
            logger.warning(f"AI generation failed: {e}")
            return None

    def _build_architecture_context(self, arch: Architecture) -> str:
        """Build a concise architecture description for AI context."""
        lines = ["Architecture Overview:"]

        lines.append("\nComponents:")
        for comp in arch.components:
            ports = f", ports: {comp.exposed_ports}" if comp.exposed_ports else ""
            lines.append(f"  - {comp.name} (type: {comp.type.value}, zone: {comp.trust_zone.value}{ports})")

        lines.append("\nData Flows:")
        for flow in arch.flows:
            encrypted = "encrypted" if flow.is_encrypted else "plaintext"
            lines.append(f"  - {flow.source} -> {flow.destination} ({flow.protocol}, {encrypted})")

        lines.append("\nTrust Boundaries:")
        for boundary in arch.boundaries:
            lines.append(f"  - {boundary.name}: {', '.join(boundary.components)}")

        lines.append("\nSensitive Assets:")
        for asset in arch.assets:
            lines.append(f"  - {asset.name} ({asset.type.value}) at {asset.location}")

        return "\n".join(lines)

    def _enhance_batch(self, threats: list[Threat], arch_context: str) -> list[Threat]:
        """Enhance a batch of threats with AI explanations."""
        threats_desc = []
        for i, t in enumerate(threats):
            evidence_str = "; ".join(t.evidence)
            threats_desc.append(
                f"{i+1}. [{t.severity.value.upper()}] {t.stride_category.value}: {t.title}\n"
                f"   Evidence: {evidence_str}\n"
                f"   Boundary: {t.boundary}"
            )

        prompt = f"""You are a Principal Security Engineer performing threat analysis.

{arch_context}

The following threats were identified by deterministic STRIDE analysis.
For each threat, provide:
1. A clear, specific explanation of why this matters in production (2-3 sentences)
2. A specific, actionable mitigation (not generic advice)

CRITICAL: Base your response ONLY on the observed evidence. Do NOT invent vulnerabilities.

Threats:
{chr(10).join(threats_desc)}

Respond in JSON format:
{{
  "threats": [
    {{
      "index": 1,
      "explanation": "...",
      "mitigation": "..."
    }}
  ]
}}"""

        response = self._generate(prompt)
        if not response:
            return threats

        try:
            # Extract JSON from response (handle markdown code blocks)
            json_str = response
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str:
                json_str = json_str.split("```")[1].split("```")[0]

            data = json.loads(json_str.strip())
            enhancements = {e["index"] - 1: e for e in data.get("threats", [])}

            enhanced = []
            for i, threat in enumerate(threats):
                if i in enhancements:
                    e = enhancements[i]
                    enhanced.append(threat.model_copy(update={
                        "explanation": e.get("explanation", threat.explanation),
                        "mitigation": e.get("mitigation", threat.mitigation),
                    }))
                else:
                    enhanced.append(threat)
            return enhanced
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            logger.warning(f"Failed to parse AI response: {e}")
            return threats

    def _build_prioritization_prompt(self, threats: list[Threat]) -> str:
        """Build a prompt for threat prioritization."""
        threats_list = "\n".join(
            f"- ID:{t.id} [{t.severity.value}] {t.title} (boundary: {t.boundary})"
            for t in threats
        )
        return f"""You are a Principal Security Engineer.

Given these threats from a STRIDE analysis, rank the top 5 most likely to cause
a real production security incident. Consider exploitability and blast radius.

Threats:
{threats_list}

Respond with just the threat IDs in priority order, one per line:
ID1
ID2
ID3
ID4
ID5"""

    def _apply_prioritization(self, threats: list[Threat], response: str) -> list[Threat]:
        """Apply AI prioritization ordering to threats."""
        try:
            priority_ids = [line.strip() for line in response.strip().split("\n") if line.strip()]
            id_to_priority = {tid: i for i, tid in enumerate(priority_ids)}

            def sort_key(t: Threat) -> tuple:
                # Prioritized threats first, then by severity
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                priority = id_to_priority.get(t.id, 999)
                return (priority, severity_order.get(t.severity.value, 4))

            return sorted(threats, key=sort_key)
        except Exception:
            return threats

    def _build_delta_summary_prompt(self, delta: ThreatDelta, arch: Architecture) -> str:
        """Build a prompt for delta summarization."""
        parts = []
        if delta.new_threats:
            parts.append("New threats:")
            for t in delta.new_threats[:5]:  # Cap at 5
                evidence_str = "; ".join(t.evidence)
                parts.append(f"  - [{t.severity.value}] {t.title}: {evidence_str}")

        if delta.mitigated_threats:
            parts.append("Mitigated threats:")
            for t in delta.mitigated_threats[:5]:
                parts.append(f"  - {t.title}")

        if delta.new_components:
            parts.append(f"New components: {', '.join(delta.new_components)}")
        if delta.removed_components:
            parts.append(f"Removed components: {', '.join(delta.removed_components)}")
        if delta.new_boundaries:
            parts.append(f"New boundaries: {', '.join(delta.new_boundaries)}")

        return f"""You are a Principal Security Engineer writing a brief PR comment summary.

Architectural changes detected:
{chr(10).join(parts)}

Write a 2-3 sentence executive summary of the security impact of these changes.
Focus on what's most important for the development team to know.
Be concise and actionable. Do not use markdown formatting."""
