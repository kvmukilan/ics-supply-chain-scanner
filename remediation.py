"""LLM-powered remediation generator using Azure OpenAI via LangChain.

Generates IEC 62443-mapped remediation playbooks for each finding.
Falls back to template-based remediation if LLM is unavailable.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from config import AzureOpenAIConfig
from models import Finding

logger = logging.getLogger(__name__)

# IEC 62443 Foundational Requirements reference
IEC_62443_FR = {
    "FR1": "Identification and Authentication Control",
    "FR2": "Use Control",
    "FR3": "System Integrity",
    "FR4": "Data Confidentiality",
    "FR5": "Restricted Data Flow",
    "FR6": "Timely Response to Events",
    "FR7": "Resource Availability",
}

SYSTEM_PROMPT = """You are an ICS/OT cybersecurity remediation expert. Given a vulnerability finding
for an industrial control system asset, generate a concise remediation playbook.

Your response MUST be valid JSON with this structure:
{{
    "iec_62443_mappings": ["FR1: Identification and Authentication Control", ...],
    "risk_context": "Brief OT-specific risk context for this vulnerability",
    "immediate_actions": ["action1", "action2"],
    "short_term_remediation": ["step1", "step2"],
    "long_term_remediation": ["step1", "step2"],
    "compensating_controls": ["control1", "control2"],
    "verification_steps": ["step1", "step2"]
}}

Guidelines:
- Map to specific IEC 62443-3-3 System Requirements (SR) where possible
- Consider the asset's Purdue level when recommending network controls
- For L0/L1 devices, prioritize compensating controls over patches (downtime risk)
- Always suggest monitoring/detection as a compensating control
- Be specific: reference actual protocols (Modbus, DNP3, OPC UA) and controls (ACLs, VLAN, firewall rules)
- If in CISA KEV, emphasize urgency and federal compliance deadline
"""


def _build_langchain_chain(config: AzureOpenAIConfig):
    """Build a LangChain chain for remediation generation.

    Uses AzureChatOpenAI with a structured prompt template and
    JsonOutputParser for reliable JSON extraction.
    """
    from langchain_openai import AzureChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import JsonOutputParser

    llm = AzureChatOpenAI(
        azure_endpoint=config.endpoint,
        api_key=config.api_key,
        azure_deployment=config.deployment,
        api_version=config.api_version,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", "{finding_prompt}"),
    ])

    parser = JsonOutputParser()

    chain = prompt | llm | parser
    return chain


class RemediationGenerator:
    """Generate IEC 62443-mapped remediation using Azure OpenAI via LangChain."""

    def __init__(self, config: AzureOpenAIConfig):
        self.config = config
        self._enabled = bool(config.endpoint and config.api_key)
        self._chain = None
        if not self._enabled:
            logger.warning(
                "Azure OpenAI not configured. Using template-based remediation."
            )

    def _get_chain(self):
        """Lazy-initialize the LangChain chain."""
        if self._chain is None and self._enabled:
            try:
                self._chain = _build_langchain_chain(self.config)
                logger.info("LangChain Azure OpenAI chain initialized")
            except Exception as e:
                logger.error(f"Failed to initialize LangChain chain: {e}")
                self._enabled = False
        return self._chain

    def _build_finding_prompt(self, finding: Finding) -> str:
        """Build the LLM prompt for a specific finding."""
        kev_info = ""
        if finding.in_kev and finding.kev_entry:
            kev_info = (
                f"\nCISA KEV Status: ACTIVELY EXPLOITED"
                f"\n  - Date Added: {finding.kev_entry.date_added}"
                f"\n  - Due Date: {finding.kev_entry.due_date}"
                f"\n  - Required Action: {finding.kev_entry.required_action}"
                f"\n  - Ransomware Use: {finding.kev_entry.known_ransomware_use}"
            )

        return f"""Generate a remediation playbook for:

Asset: {finding.asset.name}
  Vendor: {finding.asset.vendor}
  Model: {finding.asset.model}
  Firmware: {finding.asset.firmware_version}
  Purdue Level: {finding.asset.purdue_level}
  Network Zone: {finding.asset.network_zone}
  Exposure: {finding.asset.exposure.value}
  Patch Status: {finding.asset.patch_status.value}

Vulnerability: {finding.cve.cve_id}
  CVSS Score: {finding.cve.cvss_base_score}
  Vector: {finding.cve.cvss_vector}
  Description: {finding.cve.description}
  CWE: {', '.join(finding.cve.weaknesses) if finding.cve.weaknesses else 'N/A'}
{kev_info}

OT Risk Score: {finding.ot_risk_score:.2f} ({finding.ot_severity.value})
Score Breakdown: {json.dumps(finding.score_breakdown, indent=2)}

Respond with JSON only. No markdown, no code fences."""

    async def generate(self, finding: Finding) -> Finding:
        """Generate remediation for a finding using LangChain."""
        if not self._enabled:
            return self._template_remediation(finding)

        chain = self._get_chain()
        if chain is None:
            return self._template_remediation(finding)

        try:
            prompt_text = self._build_finding_prompt(finding)
            # LangChain's ainvoke for async execution
            remediation = await chain.ainvoke({"finding_prompt": prompt_text})

            finding.iec_62443_mappings = remediation.get("iec_62443_mappings", [])
            finding.remediation = json.dumps(remediation, indent=2)
            logger.debug(f"LangChain remediation generated for {finding.cve.cve_id}")
            return finding

        except Exception as e:
            logger.warning(f"LangChain remediation failed for {finding.cve.cve_id}: {e}")
            return self._template_remediation(finding)

    def _template_remediation(self, finding: Finding) -> Finding:
        """Fallback template-based remediation when LLM is unavailable."""
        asset = finding.asset
        cve = finding.cve
        mappings = []
        actions = []
        compensating = []

        # Map based on CWE patterns
        cwe_str = " ".join(cve.weaknesses).lower()
        if any(k in cwe_str for k in ["cwe-287", "cwe-306", "auth"]):
            mappings.append("FR1: Identification and Authentication Control (IEC 62443-3-3 SR 1.1)")
            actions.append("Enforce authentication on all access points per SR 1.1")
        if any(k in cwe_str for k in ["cwe-276", "cwe-732", "cwe-269"]):
            mappings.append("FR2: Use Control (IEC 62443-3-3 SR 2.1)")
            actions.append("Implement least-privilege access per SR 2.1")
        if any(k in cwe_str for k in ["cwe-120", "cwe-787", "cwe-119", "overflow"]):
            mappings.append("FR3: System Integrity (IEC 62443-3-3 SR 3.2)")
            actions.append("Apply input validation and firmware update per SR 3.2")
        if any(k in cwe_str for k in ["cwe-200", "cwe-312", "cwe-319"]):
            mappings.append("FR4: Data Confidentiality (IEC 62443-3-3 SR 4.1)")
            actions.append("Encrypt communications per SR 4.1")

        # Network segmentation is always relevant for OT
        mappings.append("FR5: Restricted Data Flow (IEC 62443-3-3 SR 5.1)")
        compensating.append(
            f"Implement network segmentation per SR 5.1 — "
            f"restrict traffic to/from {asset.name} at Purdue Level {asset.purdue_level}"
        )

        # Monitoring
        mappings.append("FR6: Timely Response to Events (IEC 62443-3-3 SR 6.1)")
        compensating.append(
            f"Deploy IDS/monitoring for {asset.name} to detect exploitation attempts for {cve.cve_id}"
        )

        # Patch-specific
        if asset.patch_status.value == "available":
            actions.insert(0, f"Apply vendor patch for {cve.cve_id} during next maintenance window")
        elif asset.patch_status.value == "eol":
            actions.append(f"Plan migration from EOL device {asset.model}")
            compensating.append("Implement virtual patching via firewall/IPS rules")
        else:
            compensating.append("Deploy compensating controls: ACL + IDS until patch is available")

        # KEV urgency
        if finding.in_kev and finding.kev_entry:
            actions.insert(
                0,
                f"URGENT: CISA KEV deadline {finding.kev_entry.due_date} — "
                f"{finding.kev_entry.required_action}",
            )

        if not mappings:
            mappings.append("FR3: System Integrity (IEC 62443-3-3 SR 3.2)")

        remediation_doc = {
            "iec_62443_mappings": mappings,
            "risk_context": (
                f"{cve.cve_id} ({cve.severity.value}, CVSS {cve.cvss_base_score}) affects "
                f"{asset.vendor} {asset.model} at Purdue Level {asset.purdue_level}. "
                f"OT Risk Score: {finding.ot_risk_score:.2f}."
            ),
            "immediate_actions": actions,
            "compensating_controls": compensating,
            "verification_steps": [
                f"Validate patch/mitigation applied on {asset.name}",
                f"Run vulnerability scan to confirm {cve.cve_id} remediated",
                "Review IDS logs for exploitation indicators",
            ],
        }

        finding.iec_62443_mappings = mappings
        finding.remediation = json.dumps(remediation_doc, indent=2)
        return finding

    async def generate_batch(
        self, findings: list[Finding], max_concurrent: int = 3
    ) -> list[Finding]:
        """Generate remediation for multiple findings with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _generate_with_limit(f: Finding) -> Finding:
            async with semaphore:
                return await self.generate(f)

        results = await asyncio.gather(
            *[_generate_with_limit(f) for f in findings],
            return_exceptions=True,
        )

        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Remediation generation failed: {result}")
                processed.append(self._template_remediation(findings[i]))
            else:
                processed.append(result)

        return processed
