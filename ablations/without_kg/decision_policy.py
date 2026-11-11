"""Deterministic constraints for the unified Final Judge output."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass

from agent_schemas import AgentFusionDecision, AgentVerificationReport
from schemas import BinaryDiagnosis, DiagnosisResult


def _normalize_cwe(value: str) -> str:
    match = re.search(r"(?i)(?:CWE[-_ ]*)?(\d+)", value or "")
    return f"CWE-{match.group(1)}" if match else ""


def _supported_agent_cwes(reports: list[AgentVerificationReport]) -> list[str]:
    candidates = []
    verifier_reports = sorted(
        (
            report
            for report in reports
            if report.agent_name != "DefenseAgent" and report.verdict == "supported"
        ),
        key=lambda report: report.confidence,
        reverse=True,
    )
    for report in verifier_reports:
        cwe = _normalize_cwe(report.recommended_cwe or report.target_cwe)
        if cwe and cwe not in candidates:
            candidates.append(cwe)
    return candidates


def _has_concrete_evidence(report: AgentVerificationReport, evidence_types: set[str]) -> bool:
    for evidence in list(report.code_evidence) + list(report.defense_evidence):
        if evidence.evidence_type in evidence_types and evidence.line_or_snippet.strip():
            return True
    return False


def _has_strong_supported_verifier(reports: list[AgentVerificationReport]) -> bool:
    return any(
        report.agent_name != "DefenseAgent"
        and report.verdict == "supported"
        and report.confidence >= 0.85
        and _has_concrete_evidence(report, {"dangerous_operation", "missing_check"})
        for report in reports
    )


def _has_strong_defense_gate(reports: list[AgentVerificationReport]) -> bool:
    return any(
        report.agent_name == "DefenseAgent"
        and report.verdict == "not_supported"
        and report.confidence >= 0.85
        and _has_concrete_evidence(report, {"defense"})
        for report in reports
    )


@dataclass
class EnforcedDecision:
    decision: AgentFusionDecision
    binary_source: str
    cwe_source: str
    proposed_binary: bool
    proposed_cwe: str
    overridden_fields: list[str]


def enforce_final_decision(
    global_diagnosis: BinaryDiagnosis,
    global_preliminary_diagnosis: DiagnosisResult | None,
    reports: list[AgentVerificationReport],
    proposal: AgentFusionDecision,
) -> EnforcedDecision:
    """Apply the Hybrid-compatible binary lock and CWE priority policy."""
    decision = copy.deepcopy(proposal)
    proposed_binary = bool(proposal.is_vulnerable)
    proposed_cwe = _normalize_cwe(proposal.cwe_id)
    overridden_fields = []

    global_binary = bool(global_diagnosis.is_vulnerable)
    defense_gate_blocks = (
        global_binary
        and _has_strong_defense_gate(reports)
        and not _has_strong_supported_verifier(reports)
    )
    final_binary = False if defense_gate_blocks else global_binary

    if decision.is_vulnerable != final_binary:
        overridden_fields.append("is_vulnerable")
    decision.is_vulnerable = final_binary

    cwe_source = "none"
    if not final_binary:
        if decision.cwe_id:
            overridden_fields.append("cwe_id")
        decision.cwe_id = ""
        decision.vulnerability_type = ""
        decision.affected_lines = []
        decision.confidence = global_diagnosis.confidence
        if global_preliminary_diagnosis:
            decision.explanation = global_preliminary_diagnosis.explanation
    else:
        agent_cwes = _supported_agent_cwes(reports)
        if proposed_cwe in agent_cwes:
            selected_cwe = proposed_cwe
        elif agent_cwes:
            selected_cwe = agent_cwes[0]
        else:
            selected_cwe = _normalize_cwe(
                global_preliminary_diagnosis.cwe_id
                if global_preliminary_diagnosis
                else ""
            )

        if selected_cwe != proposed_cwe:
            overridden_fields.append("cwe_id")
        decision.cwe_id = selected_cwe
        cwe_source = "agent" if selected_cwe in agent_cwes else "global_fallback"
        if cwe_source == "global_fallback" and global_preliminary_diagnosis:
            decision.vulnerability_type = global_preliminary_diagnosis.vulnerability_type

    binary_policy = "defense_gate" if defense_gate_blocks else "global"
    decision.fusion_trace = (
        f"{decision.fusion_trace} | Constrained policy: binary={binary_policy}; "
        f"cwe_source={cwe_source}; overridden={','.join(overridden_fields) or 'none'}"
    ).strip()
    return EnforcedDecision(
        decision=decision,
        binary_source=(
            "defense_exploitability_gate"
            if defense_gate_blocks
            else "global_risk_assessment"
        ),
        cwe_source=cwe_source,
        proposed_binary=proposed_binary,
        proposed_cwe=proposed_cwe,
        overridden_fields=overridden_fields,
    )
