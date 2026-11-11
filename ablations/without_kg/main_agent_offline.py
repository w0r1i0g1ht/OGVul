# -*- coding: utf-8 -*-
"""
Multi-agent vulnerability detection entrypoint without knowledge-graph evidence.

This script uses vLLM Native Engine offline inference directly. It does not
start or call the OpenAI-compatible vLLM API server.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
import time
from pathlib import Path

import yaml

import offline_runtime as offline
from decision_policy import enforce_final_decision
from llm_compat import historical_llm_chat, llm_chat
from historical_binary_recovery import recover_historical_binary
from global_checkpoint import (
    GlobalPerceptionCheckpoint,
    load_global_checkpoints,
    save_global_checkpoints,
)
from agent_schemas import (
    AgentDetectionResult,
    AgentFusionDecision,
    AgentTask,
    AgentVerificationReport,
    OrchestratorPlan,
)
from data_loader import DataLoader
from schemas import (
    BinaryDiagnosis,
    CWEDiagnosis,
    DiagnosisResult,
    DualExtraction,
    GraphWarning,
    ReportDiagnosis,
)


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("agent_vuln_detect_without_kg_offline")


ORCHESTRATOR_SYSTEM = (
    "You are the Orchestrator Agent for a multi-agent vulnerability detection system "
    "for Oil & Gas industrial C/C++ software.\n"
    "Your job is NOT to extract code context again and NOT to make the final verdict. "
    "Use the supplied strict extraction and code-only global risk assessment to generate concrete, "
    "verifiable vulnerability hypotheses for downstream agents.\n\n"
    "Requirements:\n"
    "1. Copy entities, semantic_summary, domain, and context_possible_cwes exactly from "
    "the supplied strict extraction. Do not replace or re-extract them.\n"
    "2. Generate 1-3 concrete vulnerability_hypotheses from the source code and global "
    "risk assessment. Each hypothesis must be "
    "testable against code evidence. Use assigned_agent='VulnerabilityVerifier'.\n"
    "3. Treat the global risk assessment as a coarse opinion, not ground truth. Include only "
    "hypotheses that downstream agents can support or refute using exact source evidence.\n"
    "4. Do not propose CWE-476 only because code checks pointer == NULL. CWE-476 "
    "requires an actual dereference such as *ptr, ptr->field, ptr[index], or a call "
    "that dereferences a possibly NULL pointer.\n"
    "5. initial_risk_assessment must be one of: safe, suspicious, vulnerable, uncertain.\n\n"
    "Do not output <think> or reasoning text. The first character of your response must be '{'. "
    "Output ONLY a pure JSON object. No markdown, no extra text.\n"
    "Output schema example:\n"
    "{\n"
    '  "entities": [{"name": "modbus", "type": "Protocol", "importance": "High"}],\n'
    '  "semantic_summary": "This code parses Modbus packets and copies payload data.",\n'
    '  "domain": "Protocol",\n'
    '  "initial_risk_assessment": "suspicious",\n'
    '  "context_possible_cwes": ["CWE-787", "CWE-125"],\n'
    '  "vulnerability_hypotheses": [\n'
    '    {"hypothesis_id": "H1", "cwe_id": "CWE-787", "risk_type": "Out-of-bounds Write", '
    '"reason": "Input length may control a copy into a fixed buffer.", '
    '"assigned_agent": "VulnerabilityVerifier"}\n'
    "  ]\n"
    "}"
)


VERIFIER_SYSTEM = (
    "You are the Vulnerability Verifier Agent. You verify whether a specific vulnerability "
    "hypothesis is actually supported by the exact C/C++ code.\n\n"
    "Rules:\n"
    "1. Mark verdict='supported' only if a concrete dangerous operation remains undefended "
    "in the source code.\n"
    "2. Mark verdict='not_supported' if the source code has sufficient checks or the hypothesis "
    "does not match the implemented operation.\n"
    "3. Mark verdict='uncertain' if source-code evidence is insufficient.\n"
    "4. Focus only on the assigned task; do not make the final global decision.\n\n"
    "CWE-476 rule: a NULL check such as ptr == NULL is not a NULL-dereference vulnerability. "
    "Only support CWE-476 when the code dereferences a possibly NULL pointer through *ptr, "
    "ptr->field, ptr[index], or an equivalent call without a prior dominating NULL guard.\n\n"
    "Do not output <think> or reasoning text. The first character of your response must be '{'. "
    "Output ONLY a pure JSON object with fields: agent_name, task_id, hypothesis_id, target_cwe, "
    "code_evidence, defense_evidence, verdict, confidence, recommended_cwe, summary, retrieval_request.\n"
    "target_cwe and recommended_cwe must be single strings. code_evidence and defense_evidence "
    "must be arrays of objects: {\"evidence_type\": \"dangerous_operation|missing_check|defense|neutral\", "
    "\"line_or_snippet\": \"exact source snippet\", \"analysis\": \"why it matters\"}. "
    "Always set retrieval_request to an empty string because this ablation has no external retrieval.\n"
    "Do not include markdown."
)


DEFENSE_SYSTEM = (
    "You are the Defense Agent. Your role is to find safety defenses and counter-evidence "
    "that may refute vulnerability hypotheses in the given C/C++ code.\n\n"
    "Look for explicit bounds checks, input validation, safe APIs, RAII/smart pointer lifecycle "
    "management, lock protection, error-path cleanup, and other defenses.\n"
    "For CWE-476, NULL checks are defense evidence. They are not vulnerability evidence unless "
    "the code later dereferences the same pointer without a dominating guard.\n"
    "Judge defenses only from exact source-code evidence.\n\n"
    "Do not output <think> or reasoning text. The first character of your response must be '{'. "
    "Output ONLY a pure JSON object with fields: agent_name, task_id, hypothesis_id, target_cwe, "
    "code_evidence, defense_evidence, verdict, confidence, recommended_cwe, summary.\n"
    "target_cwe and recommended_cwe must be single strings. code_evidence and defense_evidence "
    "must be arrays of objects: {\"evidence_type\": \"dangerous_operation|missing_check|defense|neutral\", "
    "\"line_or_snippet\": \"exact source snippet\", \"analysis\": \"why it matters\"}. "
    "Only source-code facts may appear in defense_evidence.\n"
    "Limit output to at most 3 code_evidence items and at most 3 defense_evidence items. "
    "Start with the JSON object immediately; do not write analysis before JSON.\n"
    "Use verdict='not_supported' when defenses refute the risk; use 'uncertain' if unclear; "
    "use 'supported' only if missing defenses are clear. Do not include markdown."
)


FINAL_JUDGE_SYSTEM = (
    "You are the Final Judge Agent for a code-only multi-agent vulnerability detection system.\n"
    "Fuse the code-only global risk assessment, Orchestrator plan, "
    "Vulnerability Verifier reports, and Defense Agent report into one final decision.\n\n"
    "Decision rules:\n"
    "1. The global risk assessment is the default binary anchor, but apply a "
    "defense exploitability gate when source-code-specific Defense evidence "
    "refutes the suspected path and Verifier evidence is weak.\n"
    "2. Use local agents to verify evidence, select the root-cause CWE, and explain the result.\n"
    "3. At least one concrete dangerous operation must remain undefended for is_vulnerable=true.\n"
    "4. If the Defense Agent shows a source-code-specific sufficient defense, downgrade or reject the risk.\n"
    "5. Exact code evidence is stronger than either model's prior conclusion.\n"
    "6. Do not accept CWE-476 unless there is an actual dereference of a possibly NULL pointer; "
    "NULL checks alone are defense evidence, not vulnerability evidence.\n"
    "7. Do not mark vulnerable when the only support is hypothetical wording such as may/could/potential, "
    "missing context, or a generic missing-check claim without a concrete sink/source operation.\n"
    "8. If local evidence is weak, retain the global binary anchor and use the global preliminary CWE as fallback.\n"
    "9. If global and local conclusions conflict, explain which exact source evidence resolves the conflict.\n"
    "10. If vulnerable, choose the CWE that best represents the code root cause.\n"
    "11. The explanation field must be concise Chinese.\n\n"
    "Do not output <think> or reasoning text. The first character of your response must be '{'. "
    "Output ONLY a pure JSON object with fields: fusion_trace, is_vulnerable, confidence, "
    "cwe_id, vulnerability_type, explanation, affected_lines. No markdown."
)


def truncate_middle(text: str, max_chars: int, label: str = "content") -> str:
    if not max_chars or max_chars <= 0 or len(text) <= max_chars:
        return text
    keep_head = max_chars // 2
    keep_tail = max_chars - keep_head
    omitted = len(text) - max_chars
    return (
        text[:keep_head]
        + f"\n\n/* ... {label} truncated, omitted {omitted} characters ... */\n\n"
        + text[-keep_tail:]
    )


def normalize_code(code: str, max_chars: int | None = None) -> str:
    cleaned = (code or "").strip().replace("\r\n", "\n")
    if max_chars:
        cleaned = truncate_middle(cleaned, max_chars, "source code")
    return cleaned


def build_global_risk_conversation(sample, code_char_limit: int) -> list[dict]:
    assembled_prompt = build_code_only_context(sample, code_char_limit)
    user_prompt = (
        "Please objectively analyze whether the following code is safe or vulnerable, "
        "and output the result in pure JSON format:\n\n"
        f"{assembled_prompt}"
    )
    return [
        {"role": "system", "content": offline.DIAGNOSIS_SYSTEM_5A_BASE_LLM},
        {"role": "user", "content": user_prompt},
    ]


def build_code_only_context(sample, code_char_limit: int) -> str:
    return (
        "## C/C++ Source Code for Audit\n"
        f"```cpp\n{normalize_code(sample.code, code_char_limit)}\n```\n"
    )


def collect_global_cwe_candidates(
    extraction: DualExtraction,
) -> list[str]:
    candidates = set()
    values = list(extraction.context_possible_cwes)
    for value in values:
        match = re.search(r"(?i)(?:CWE[-_ ]*)?(\d+)", value or "")
        if match:
            candidates.add(f"CWE-{match.group(1)}")
    return sorted(candidates)


def build_global_cwe_conversation(
    sample,
    extraction: DualExtraction,
    code_char_limit: int,
) -> list[dict]:
    candidates = collect_global_cwe_candidates(extraction)
    candidate_text = ", ".join(candidates) if candidates else "No recommended candidates"
    return [
        {
            "role": "system",
            "content": offline.DIAGNOSIS_SYSTEM_5B.format(cwe_candidates=candidate_text),
        },
        {
            "role": "user",
            "content": (
                "Analyze the following vulnerable code and identify its ROOT CAUSE CWE ID. "
                "Output pure JSON:\n\n"
                + build_code_only_context(sample, code_char_limit)
            ),
        },
    ]


def build_global_report_conversation(
    sample,
    cwe_diagnosis: CWEDiagnosis,
    code_char_limit: int,
) -> list[dict]:
    context = build_code_only_context(sample, code_char_limit)
    cwe_info = f"{cwe_diagnosis.cwe_id} ({cwe_diagnosis.vulnerability_type})"
    return [
        {"role": "system", "content": offline.DIAGNOSIS_SYSTEM_5C},
        {
            "role": "user",
            "content": (
                f"Context:\n{context}\n\n"
                "This code has been classified as: VULNERABLE.\n"
                f"The identified root cause is: {cwe_info}.\n"
                "Please extract affected lines and provide a concise Chinese explanation "
                "in pure JSON format."
            ),
        },
    ]


def build_orchestrator_conversation(
    sample,
    extraction: DualExtraction,
    global_risk: BinaryDiagnosis,
    global_preliminary: DiagnosisResult | None,
    code_char_limit: int,
) -> list[dict]:
    user_prompt = "\n\n".join(
        [
            "Strict extraction (copy its context fields exactly):",
            extraction.model_dump_json(indent=2),
            "Code-only global risk assessment (coarse opinion, not ground truth):",
            global_risk.model_dump_json(indent=2),
            "Global preliminary vulnerability diagnosis and CWE fallback:",
            global_preliminary.model_dump_json(indent=2)
            if global_preliminary
            else "No preliminary CWE diagnosis because the global result is safe.",
            f"Source code:\n```text\n{normalize_code(sample.code, code_char_limit)}\n```",
            "Plan downstream verification tasks. Output pure JSON only.",
        ]
    )
    return [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM},
        {"role": "user", "content": user_prompt},
    ]


def agent_reports_to_text(reports: list[AgentVerificationReport], max_chars: int = 8000) -> str:
    if not reports:
        return "No agent reports."
    chunks = []
    for report in reports:
        chunks.append(
            "\n".join(
                [
                    f"Agent: {report.agent_name}",
                    f"Task: {report.task_id}",
                    f"Hypothesis: {report.hypothesis_id}",
                    f"Target CWE: {report.target_cwe}",
                    f"Verdict: {report.verdict}",
                    f"Confidence: {report.confidence}",
                    f"Recommended CWE: {report.recommended_cwe}",
                    f"Verification round: {report_get(report, 'verification_round', 1)}",
                    f"Retrieval request: {report_get(report, 'retrieval_request', '')}",
                    f"Previous verdict: {report_get(report, 'previous_verdict', '')}",
                    f"Previous summary: {report_get(report, 'previous_summary', '')}",
                    f"Code evidence: {json.dumps([e.model_dump() for e in report.code_evidence], ensure_ascii=False)}",
                    f"Defense evidence: {json.dumps([e.model_dump() for e in report.defense_evidence], ensure_ascii=False)}",
                    f"Summary: {report.summary}",
                ]
            )
        )
    return truncate_middle("\n\n".join(chunks), max_chars, "agent reports")


def report_get(report: AgentVerificationReport, field: str, default=""):
    return getattr(report, field, default)


def report_set(report: AgentVerificationReport, field: str, value) -> None:
    try:
        setattr(report, field, value)
    except ValueError:
        # Backward compatibility when an older agent_schemas.py is accidentally used.
        logger.warning(f"AgentVerificationReport has no field '{field}'; skipped setting it.")


def build_agent_user_prompt(
    sample,
    task: AgentTask,
    plan: OrchestratorPlan,
    code_char_limit: int,
    role_extra: str = "",
) -> str:
    return "\n\n".join(
        [
            f"Task ID: {task.task_id}",
            f"Hypothesis ID: {task.hypothesis_id}",
            f"Assigned role: {task.assigned_agent}",
            f"Target CWE: {task.target_cwe or 'None'}",
            f"Risk type: {task.risk_type or 'General'}",
            f"Task goal: {task.task_goal}",
            f"Orchestrator semantic summary: {plan.semantic_summary}",
            "Important for CWE-476: pointer NULL checks are not vulnerability evidence. "
            "Only an actual dereference of a possibly NULL pointer supports CWE-476.",
            role_extra,
            f"C/C++ source code:\n```cpp\n{normalize_code(sample.code, code_char_limit)}\n```",
            "Return code_evidence and defense_evidence as arrays of objects, never as strings. "
            "Do not output <think>. Output pure JSON only. The first character must be '{'.",
        ]
    )


def make_tasks(plan: OrchestratorPlan) -> list[AgentTask]:
    tasks: list[AgentTask] = []
    for idx, hypothesis in enumerate(plan.vulnerability_hypotheses[:3], 1):
        tasks.append(
            AgentTask(
                task_id=f"T{idx}",
                hypothesis_id=hypothesis.hypothesis_id or f"H{idx}",
                assigned_agent="VulnerabilityVerifier",
                target_cwe=hypothesis.cwe_id,
                risk_type=hypothesis.risk_type,
                task_goal=(
                    "Verify whether this vulnerability hypothesis is actually exploitable "
                    f"in the code: {hypothesis.reason}"
                ),
                entities=plan.entities,
                domain=plan.domain,
            )
        )

    if not tasks:
        tasks.append(
            AgentTask(
                task_id="T1",
                hypothesis_id="H1",
                assigned_agent="VulnerabilityVerifier",
                target_cwe=", ".join(plan.context_possible_cwes[:2]),
                risk_type="General vulnerability verification",
                task_goal="Verify whether the code contains any concrete undefended vulnerability.",
                entities=plan.entities,
                domain=plan.domain,
            )
        )

    tasks.append(
        AgentTask(
            task_id="TD",
            hypothesis_id="DEFENSE",
            assigned_agent="DefenseAgent",
            target_cwe=", ".join(plan.context_possible_cwes[:4]),
            risk_type="Safety counter-evidence",
            task_goal="Find concrete source-code defenses that refute the vulnerability hypotheses.",
            entities=plan.entities,
            domain=plan.domain,
        )
    )
    return tasks


def collect_cwe_candidates(plan: OrchestratorPlan) -> list[str]:
    cwes = set()
    for cwe in plan.context_possible_cwes:
        match = re.search(r"(?i)cwe[-_]?\d+", cwe or "")
        if match:
            digits = re.search(r"\d+", match.group(0))
            if digits:
                cwes.add(f"CWE-{digits.group(0)}")
    return sorted(cwes)


def init_llm(config: dict):
    llm_conf = config["llm"]["extraction"]
    model_path = llm_conf.get("model_path", "")
    if not model_path:
        raise ValueError("config.yaml is missing llm.extraction.model_path")

    os.environ["VLLM_USE_V1"] = "0"
    logger.info(f"Loading vLLM Native offline model: {model_path}")
    return offline.LLM(
        model=model_path,
        tensor_parallel_size=llm_conf.get("tensor_parallel_size", 1),
        gpu_memory_utilization=llm_conf.get("gpu_memory_utilization", 0.9),
        max_model_len=llm_conf.get("max_model_len", 16384) or 16384,
        trust_remote_code=True,
        enforce_eager=True,
        enable_prefix_caching=True,
    )


def result_filename(config: dict) -> str:
    configured = str(config.get("runtime", {}).get("result_file", "")).strip()
    if configured:
        return configured
    mode = config.get("experiment", {}).get("pipeline_mode", "unified_agent_without_kg")
    return f"detection_results_{mode}.json"


def load_existing_results(path: Path) -> dict[str, AgentDetectionResult]:
    if not path.exists():
        return {}
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
        loaded: dict[str, AgentDetectionResult] = {}
        for record in records:
            global_risk = record.get("global_risk_assessment") or {}
            if (
                not record.get("raw_global_risk_output")
                or not record.get("raw_orchestrator_output")
                or not record.get("raw_fusion_output")
                or not record.get("binary_source")
            ):
                continue
            if global_risk.get("is_vulnerable") and not record.get("raw_global_preliminary_output"):
                continue
            if any(report.get("parse_error") for report in record.get("agent_reports", [])):
                continue
            if any(not report.get("raw_output") for report in record.get("agent_reports", [])):
                continue
            obj = AgentDetectionResult.model_validate(record)
            if obj.status == "success":
                loaded[obj.sample_id] = obj
        return loaded
    except Exception as exc:
        logger.warning(f"Failed to load existing results; regenerating. reason={exc}")
        return {}


def _clean_model_text(text: str) -> str:
    cleaned = re.sub(r"<think>.*?</think>", " ", text or "", flags=re.DOTALL)
    cleaned = cleaned.replace("<think>", " ").replace("</think>", " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _summarize_natural_language(text: str, max_chars: int = 700) -> str:
    cleaned = _clean_model_text(text)
    if not cleaned:
        return "Natural-language fallback: model returned no parseable content."
    sentences = re.split(r"(?<=[.!?。！？])\s+", cleaned)
    useful = [s.strip() for s in sentences if s.strip()]
    if not useful:
        return truncate_middle(cleaned, max_chars, "fallback summary")
    selected = useful[-3:] if len(useful) >= 3 else useful
    return "Natural-language fallback: " + truncate_middle(" ".join(selected), max_chars, "fallback summary")


def _infer_verdict_from_text(text: str) -> tuple[str, float]:
    lower = _clean_model_text(text).lower()
    if not lower:
        return "uncertain", 0.5

    uncertainty_markers = [
        "without knowing",
        "hard to say",
        "cannot determine",
        "not enough information",
        "insufficient evidence",
        "uncertain",
    ]
    negative_markers = [
        "not supported",
        "does not support",
        "refute",
        "sufficient check",
        "sufficient defense",
        "appears safe",
    ]
    strong_positive_markers = [
        "hypothesis is supported",
        "is supported by",
        "therefore supported",
        "confirms",
        "clearly vulnerable",
    ]

    if any(marker in lower for marker in uncertainty_markers):
        return "uncertain", 0.5
    if any(marker in lower for marker in negative_markers):
        return "not_supported", 0.6
    if any(marker in lower for marker in strong_positive_markers):
        return "supported", 0.6
    if "could cause" in lower or "may have" in lower or "potential" in lower:
        return "uncertain", 0.5
    return "uncertain", 0.5


def natural_language_agent_fallback(
    raw_text: str,
    task: AgentTask,
    warnings: list[GraphWarning],
    parse_error: Exception,
) -> AgentVerificationReport:
    verdict, confidence = _infer_verdict_from_text(raw_text)
    recommended_cwe = task.target_cwe if verdict == "supported" else ""
    summary = _summarize_natural_language(raw_text)
    summary += f" [JSON parse fallback applied; original parser error: {parse_error}]"
    return AgentVerificationReport(
        agent_name=task.assigned_agent,
        task_id=task.task_id,
        hypothesis_id=task.hypothesis_id,
        target_cwe=task.target_cwe,
        graph_evidence=warnings,
        code_evidence=[],
        defense_evidence=[],
        verdict=verdict,
        confidence=confidence,
        recommended_cwe=recommended_cwe,
        summary=summary,
        raw_output=raw_text,
        parse_error="",
    )


def _is_auto_filled(value: object) -> bool:
    text = str(value or "").strip()
    return not text or text.startswith("Not provided by model")


def validate_agent_report_shape(report: AgentVerificationReport) -> None:
    """Reject partial JSON objects, such as an inner evidence item, parsed as a full report."""
    missing = []
    if _is_auto_filled(report.agent_name):
        missing.append("agent_name")
    if _is_auto_filled(report.task_id):
        missing.append("task_id")
    if _is_auto_filled(report.verdict):
        missing.append("verdict")
    if _is_auto_filled(report.summary):
        missing.append("summary")
    if report.verdict not in {"supported", "not_supported", "uncertain"}:
        missing.append("valid_verdict")
    if missing:
        raise ValueError(
            "Incomplete AgentVerificationReport parsed from partial JSON: "
            + ", ".join(missing)
        )


def _has_null_deref_pattern(text: str) -> bool:
    if not text:
        return False
    if "->" in text:
        return True
    if re.search(r"(?<![A-Za-z0-9_])\*\s*[A-Za-z_][A-Za-z0-9_]*", text):
        return True
    if re.search(r"\b(?:memcpy|strcpy|strlen|strcmp|memmove|sprintf|snprintf)\s*\(", text):
        return True
    return False


def normalize_agent_report_semantics(report: AgentVerificationReport) -> AgentVerificationReport:
    cwe_text = f"{report.target_cwe} {report.recommended_cwe}".upper()
    if "CWE-476" not in cwe_text or report.verdict != "supported":
        return report

    evidence_text = " ".join(
        [e.line_or_snippet + " " + e.analysis for e in report.code_evidence + report.defense_evidence]
    )
    if _has_null_deref_pattern(evidence_text):
        return report

    report.verdict = "uncertain"
    report.confidence = min(report.confidence, 0.5)
    report.summary = (
        "CWE-476 evidence downgraded: NULL checks or pointer assignments alone do not prove "
        "a NULL pointer dereference. " + report.summary
    )
    return report


def _report_text(report: AgentVerificationReport) -> str:
    parts = [report.summary or ""]
    for evidence in report.code_evidence + report.defense_evidence:
        parts.append(evidence.evidence_type or "")
        parts.append(evidence.line_or_snippet or "")
        parts.append(evidence.analysis or "")
    return " ".join(parts).lower()


def _has_concrete_dangerous_evidence(report: AgentVerificationReport) -> bool:
    if report.verdict != "supported" or report.confidence < 0.75:
        return False
    text = _report_text(report)
    weak_markers = [
        "potential",
        "may ",
        "could ",
        "without knowing",
        "insufficient",
        "uncertain",
        "not enough",
        "missing context",
        "可能",
    ]
    if any(marker in text for marker in weak_markers) and report.confidence < 0.85:
        return False
    dangerous_items = [
        evidence for evidence in report.code_evidence
        if evidence.evidence_type in {"dangerous_operation", "missing_check"}
    ]
    if not dangerous_items:
        return False
    concrete_markers = [
        "[",
        "]",
        "memcpy",
        "strcpy",
        "sprintf",
        "free(",
        "delete",
        "printf(",
        "scanf(",
        "++",
        "--",
        "*",
        "->",
    ]
    return any(
        any(marker in (item.line_or_snippet or "") for marker in concrete_markers)
        for item in dangerous_items
    )


def _defense_has_specific_checks(report: AgentVerificationReport) -> bool:
    if report.agent_name != "DefenseAgent" or report.confidence < 0.75:
        return False
    if any(
        evidence.evidence_type in {"dangerous_operation", "missing_check"}
        for evidence in report.code_evidence
    ):
        return False
    text = _report_text(report)
    defense_markers = [
        "bounds check",
        "range check",
        "length check",
        "null check",
        "mutex",
        "smart pointer",
        "raii",
        "validation",
        "guard",
        "防御",
        "检查",
    ]
    return any(marker in text for marker in defense_markers)


_EVIDENCE_TOKEN_STOPWORDS = {
    "about",
    "after",
    "against",
    "analysis",
    "array",
    "before",
    "bounds",
    "buffer",
    "check",
    "checked",
    "code",
    "could",
    "data",
    "defense",
    "does",
    "evidence",
    "from",
    "function",
    "guard",
    "input",
    "length",
    "line",
    "missing",
    "null",
    "operation",
    "pointer",
    "range",
    "safe",
    "safety",
    "size",
    "source",
    "summary",
    "that",
    "this",
    "value",
    "validation",
    "with",
    "without",
}


def _evidence_tokens(text: str) -> set[str]:
    tokens = set()
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text or ""):
        token = token.lower()
        if token not in _EVIDENCE_TOKEN_STOPWORDS and not token.startswith("cwe"):
            tokens.add(token)
    return tokens


def _risk_evidence_tokens(report: AgentVerificationReport) -> set[str]:
    tokens: set[str] = set()
    for evidence in report.code_evidence:
        if evidence.evidence_type in {"dangerous_operation", "missing_check"}:
            tokens.update(_evidence_tokens(evidence.line_or_snippet or ""))
            tokens.update(_evidence_tokens(evidence.analysis or ""))
    return tokens


def _defense_evidence_tokens(report: AgentVerificationReport) -> set[str]:
    tokens = _evidence_tokens(report.summary or "")
    for evidence in report.code_evidence + report.defense_evidence:
        tokens.update(_evidence_tokens(evidence.line_or_snippet or ""))
        tokens.update(_evidence_tokens(evidence.analysis or ""))
    return tokens


def _defense_overlaps_supported_risk(
    defense_report: AgentVerificationReport,
    supported_reports: list[AgentVerificationReport],
) -> bool:
    if defense_report.verdict != "not_supported" or not _defense_has_specific_checks(defense_report):
        return False
    defense_tokens = _defense_evidence_tokens(defense_report)
    if not defense_tokens:
        return False
    risk_tokens: set[str] = set()
    for report in supported_reports:
        risk_tokens.update(_risk_evidence_tokens(report))
    if not risk_tokens:
        return False
    return bool(defense_tokens & risk_tokens)


def _supported_cwe(reports: list[AgentVerificationReport]) -> str:
    for report in reports:
        if report.recommended_cwe:
            return report.recommended_cwe
        if report.target_cwe:
            return report.target_cwe
    return ""


def build_result(sample, mode: str) -> AgentDetectionResult:
    return AgentDetectionResult(
        sample_id=sample.sample_id,
        source_type=sample.source_type,
        ground_truth_label=sample.label,
        ground_truth_cwe=sample.cwe_id,
        pipeline_mode=mode,
        status="pending",
    )


def choose_samples(samples: list, args) -> list:
    if args.sample:
        chosen = [s for s in samples if s.sample_id == args.sample]
        if not chosen:
            raise ValueError(f"sample not found: {args.sample}")
        return chosen
    if args.test:
        count = min(10, len(samples))
        return random.sample(samples, count) if len(samples) > count else samples
    return samples


def main():
    parser = argparse.ArgumentParser(description="Code-only multi-agent vulnerability detection with offline vLLM")
    parser.add_argument("--config", type=str, default="config.yaml")
    parser.add_argument("--test", action="store_true", help="run a small random sample")
    parser.add_argument("--sample", type=str, default="", help="run only the specified sample id")
    parser.add_argument("--batch_size", type=int, default=32, help="kept for compatibility; vLLM schedules internally")
    args = parser.parse_args()

    start = time.time()
    config_path = Path(__file__).parent / args.config
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    runtime_conf = config.get("runtime", {})
    mode = config.get("experiment", {}).get("pipeline_mode", "kg_rag")
    agent_code_char_limit = int(runtime_conf.get("agent_code_char_limit", 12000))
    global_risk_code_char_limit = int(runtime_conf.get("global_risk_code_char_limit", 10000))
    agent_fusion_code_char_limit = int(runtime_conf.get("agent_fusion_code_char_limit", 8000))
    orchestrator_retry_max_attempts = max(
        1,
        int(runtime_conf.get("orchestrator_retry_max_attempts", 3)),
    )

    output_dir = Path(config["paths"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / result_filename(config)
    global_checkpoint_version = str(
        runtime_conf.get("global_checkpoint_version", "hybrid-global-v1")
    )
    global_checkpoint_name = str(
        runtime_conf.get(
            "global_checkpoint_file",
            f"{output_path.stem}_global_checkpoint.json",
        )
    )
    global_checkpoint_path = output_dir / global_checkpoint_name

    loader = DataLoader(config["paths"]["cve_dir"], config["paths"]["synthetic_dir"])
    all_samples = loader.load_all()
    samples = choose_samples(all_samples, args)
    logger.info(f"Selected samples: {len(samples)}")

    existing = load_existing_results(output_path)
    pending_samples = [sample for sample in samples if sample.sample_id not in existing]
    if not pending_samples:
        logger.info("All selected samples already have complete results.")
        return

    llm = init_llm(config)
    llm_conf = config["llm"]["diagnosis"]
    sampling_global_json = offline.SamplingParams(max_tokens=4096, temperature=0.0)
    sampling_global_report = offline.SamplingParams(max_tokens=4096, temperature=0.2)
    sampling_json = offline.SamplingParams(max_tokens=2048, temperature=0.0)
    sampling_report = offline.SamplingParams(
        max_tokens=min(2048, llm_conf.get("max_tokens", 4096)),
        temperature=0.1,
    )

    results = {sample.sample_id: build_result(sample, mode) for sample in pending_samples}
    global_checkpoints = load_global_checkpoints(
        global_checkpoint_path,
        global_checkpoint_version,
    )
    restored_global_count = 0
    for sample in pending_samples:
        checkpoint = global_checkpoints.get(sample.sample_id)
        if checkpoint is None:
            continue
        checkpoint.restore_into(results[sample.sample_id])
        restored_global_count += 1
    global_pending_samples = [
        sample for sample in pending_samples if sample.sample_id not in global_checkpoints
    ]
    logger.info(
        "Global perception checkpoint | "
        f"restored={restored_global_count} pending={len(global_pending_samples)} "
        f"path={global_checkpoint_path}"
    )

    logger.info("[STAGE 1/7] Strict semantic extraction...")
    extraction_conversations = []
    for sample in global_pending_samples:
        extraction_conversations.append(
            [
                {"role": "system", "content": offline.EXTRACTION_SYSTEM},
                {
                    "role": "user",
                    "content": (
                        "Please analyze the following C/C++ code and output the result "
                        "in pure JSON format:\n\n"
                        f"```cpp\n{normalize_code(sample.code, global_risk_code_char_limit)}\n```"
                    ),
                },
            ]
        )

    extraction_outputs = historical_llm_chat(
        llm,
        extraction_conversations,
        sampling_params=sampling_global_json,
        use_tqdm=True,
    ) if extraction_conversations else []
    for sample, out in zip(global_pending_samples, extraction_outputs):
        result = results[sample.sample_id]
        raw_text = out.outputs[0].text
        result.raw_extraction_output = f"[thinking]\n{raw_text}"
        try:
            result.extraction = offline.parse_json_output(raw_text, DualExtraction)
        except Exception as exc:
            logger.error(f"{sample.sample_id} Step 2 extraction parse failed: {exc}")
            result.status = "error"
            result.error_message = f"Step 2 JSON parse error: {exc}"

    logger.info("[STAGE 2/7] Code-only global context preparation...")
    for sample in global_pending_samples:
        result = results[sample.sample_id]
        result.global_graph_warnings = []
        result.graph_warnings = []

    logger.info("[STAGE 3/7] Code-only global risk assessment...")
    global_conversations = []
    global_samples = []
    for sample in global_pending_samples:
        result = results[sample.sample_id]
        if result.status == "error" or not result.extraction:
            continue
        global_conversations.append(
            build_global_risk_conversation(
                sample,
                global_risk_code_char_limit,
            )
        )
        global_samples.append(sample)

    global_outputs = historical_llm_chat(
        llm,
        global_conversations,
        sampling_params=sampling_global_json,
        use_tqdm=True,
    ) if global_conversations else []
    for sample, out in zip(global_samples, global_outputs):
        result = results[sample.sample_id]
        raw_text = out.outputs[0].text
        result.raw_global_risk_output = raw_text
        try:
            result.global_risk_assessment = offline.parse_json_output(
                raw_text,
                BinaryDiagnosis,
            )
        except Exception as exc:
            logger.error(
                f"{sample.sample_id} Step 5A parse failed; applying historical keyword fallback: {exc}"
            )
            result.global_risk_assessment = recover_historical_binary(raw_text)
            logger.info(
                f"[5A FALLBACK] {sample.sample_id} vulnerable="
                f"{result.global_risk_assessment.is_vulnerable}"
            )

    logger.info("[STAGE 3B/7] Global preliminary CWE diagnosis...")
    cwe_conversations = []
    cwe_samples = []
    for sample in global_pending_samples:
        result = results[sample.sample_id]
        global_risk = result.global_risk_assessment
        if result.status == "error" or not result.extraction or not global_risk:
            continue
        if not global_risk.is_vulnerable:
            result.global_preliminary_diagnosis = DiagnosisResult(
                graph_warning_critique=global_risk.graph_warning_critique,
                code_logic_analysis=global_risk.code_logic_analysis,
                is_vulnerable=False,
                confidence=global_risk.confidence,
                cwe_id="",
                vulnerability_type="",
                explanation="Global perception classified the sample as safe.",
                affected_lines=[],
            )
            continue
        cwe_conversations.append(
            build_global_cwe_conversation(
                sample,
                result.extraction,
                global_risk_code_char_limit,
            )
        )
        cwe_samples.append(sample)

    cwe_outputs = historical_llm_chat(
        llm,
        cwe_conversations,
        sampling_params=sampling_global_json,
        use_tqdm=True,
    ) if cwe_conversations else []
    cwe_results: dict[str, CWEDiagnosis] = {}
    for sample, out in zip(cwe_samples, cwe_outputs):
        result = results[sample.sample_id]
        raw_text = out.outputs[0].text
        result.raw_global_preliminary_output = f"[5B]\n{raw_text}"
        try:
            cwe_results[sample.sample_id] = offline.parse_json_output(raw_text, CWEDiagnosis)
        except Exception as exc:
            cwe_match = re.search(r"(?i)cwe[-_ ]?(\d+)", raw_text)
            if cwe_match:
                cwe_results[sample.sample_id] = CWEDiagnosis(
                    cwe_id=f"CWE-{cwe_match.group(1)}",
                    vulnerability_type="Regex fallback from global diagnosis",
                )
            else:
                logger.warning(f"{sample.sample_id} global CWE parse failed: {exc}")
                cwe_results[sample.sample_id] = CWEDiagnosis()

    logger.info("[STAGE 3C/7] Global preliminary report generation...")
    report_conversations = []
    report_samples = []
    for sample in cwe_samples:
        result = results[sample.sample_id]
        cwe_diagnosis = cwe_results.get(sample.sample_id, CWEDiagnosis())
        report_conversations.append(
            build_global_report_conversation(
                sample,
                cwe_diagnosis,
                global_risk_code_char_limit,
            )
        )
        report_samples.append(sample)

    report_outputs = historical_llm_chat(
        llm,
        report_conversations,
        sampling_params=sampling_global_report,
        use_tqdm=True,
    ) if report_conversations else []
    for sample, out in zip(report_samples, report_outputs):
        result = results[sample.sample_id]
        global_risk = result.global_risk_assessment
        cwe_diagnosis = cwe_results.get(sample.sample_id, CWEDiagnosis())
        raw_text = out.outputs[0].text
        result.raw_global_preliminary_output += f"\n\n[5C]\n{raw_text}"
        try:
            report_diagnosis = offline.parse_json_output(raw_text, ReportDiagnosis)
        except Exception as exc:
            logger.warning(f"{sample.sample_id} global report parse failed; using audit text: {exc}")
            report_diagnosis = ReportDiagnosis(
                explanation=global_risk.code_logic_analysis if global_risk else "",
                affected_lines=[],
            )
        result.global_preliminary_diagnosis = DiagnosisResult(
            graph_warning_critique=global_risk.graph_warning_critique,
            code_logic_analysis=global_risk.code_logic_analysis,
            is_vulnerable=True,
            confidence=global_risk.confidence,
            cwe_id=cwe_diagnosis.cwe_id,
            vulnerability_type=cwe_diagnosis.vulnerability_type,
            explanation=report_diagnosis.explanation,
            affected_lines=report_diagnosis.affected_lines,
        )

    new_global_checkpoints = 0
    for sample in global_pending_samples:
        result = results[sample.sample_id]
        if result.status == "error":
            continue
        try:
            global_checkpoints[sample.sample_id] = GlobalPerceptionCheckpoint.from_result(
                result,
                global_checkpoint_version,
            )
            new_global_checkpoints += 1
        except ValueError as exc:
            logger.error(f"{sample.sample_id} global perception checkpoint skipped: {exc}")
            result.status = "error"
            result.error_message = str(exc)
    if new_global_checkpoints:
        save_global_checkpoints(global_checkpoint_path, global_checkpoints)
        logger.info(
            "Global perception checkpoint saved | "
            f"new={new_global_checkpoints} total={len(global_checkpoints)} "
            f"path={global_checkpoint_path}"
        )

    logger.info("[STAGE 4/7] Orchestrator planning from global assessment...")
    orch_samples = []
    for sample in pending_samples:
        result = results[sample.sample_id]
        if result.status == "error" or not result.extraction or not result.global_risk_assessment:
            continue
        orch_samples.append(sample)

    orch_pending = list(orch_samples)
    last_orchestrator_errors: dict[str, str] = {}
    for attempt in range(1, orchestrator_retry_max_attempts + 1):
        if not orch_pending:
            break
        logger.info(
            f"Orchestrator attempt {attempt}/{orchestrator_retry_max_attempts}: "
            f"samples={len(orch_pending)}"
        )
        conversations = []
        for sample in orch_pending:
            result = results[sample.sample_id]
            conversation = build_orchestrator_conversation(
                sample,
                result.extraction,
                result.global_risk_assessment,
                result.global_preliminary_diagnosis,
                agent_code_char_limit,
            )
            if attempt > 1:
                conversation.append(
                    {
                        "role": "user",
                        "content": (
                            "The previous response could not be parsed. Return exactly one complete "
                            "JSON object matching the requested schema. Do not output reasoning, "
                            "markdown, or <think>."
                        ),
                    }
                )
            conversations.append(conversation)

        outputs = llm_chat(
            llm,
            conversations,
            sampling_params=sampling_json,
            use_tqdm=True,
            enable_thinking=(attempt == 1),
        )
        failed_samples = []
        for sample, out in zip(orch_pending, outputs):
            result = results[sample.sample_id]
            raw_text = out.outputs[0].text
            result.raw_orchestrator_output = raw_text
            try:
                plan = offline.parse_json_output(raw_text, OrchestratorPlan)
                plan.entities = list(result.extraction.entities)
                plan.semantic_summary = result.extraction.semantic_summary
                plan.domain = result.extraction.domain
                plan.context_possible_cwes = list(result.extraction.context_possible_cwes)
                result.orchestrator_plan = plan
                result.agent_tasks = make_tasks(plan)
                last_orchestrator_errors.pop(sample.sample_id, None)
            except Exception as exc:
                last_orchestrator_errors[sample.sample_id] = str(exc)
                failed_samples.append(sample)
        orch_pending = failed_samples

    for sample in orch_pending:
        result = results[sample.sample_id]
        error = last_orchestrator_errors.get(sample.sample_id, "unknown parse failure")
        logger.error(f"{sample.sample_id} orchestrator parse failed after retries: {error}")
        result.status = "error"
        result.error_message = f"orchestrator parse failed after retries: {error}"

    logger.info("[STAGE 5/7] Preparing code-only agent tasks...")
    task_items = []
    for sample in pending_samples:
        result = results[sample.sample_id]
        plan = result.orchestrator_plan
        if result.status == "error" or not plan:
            continue
        result.global_graph_warnings = []
        result.graph_warnings = []
        for task in result.agent_tasks:
            task_items.append((sample, task))

    logger.info("[STAGE 6/7] Verifier and Defense agents...")
    agent_conversations = []
    valid_task_items = []
    report_slots: dict[tuple[str, str], int] = {}
    for sample, task in task_items:
        result = results[sample.sample_id]
        plan = result.orchestrator_plan
        if not plan:
            continue
        warnings: list[GraphWarning] = []
        system_prompt = DEFENSE_SYSTEM if task.assigned_agent == "DefenseAgent" else VERIFIER_SYSTEM
        role_extra = (
            "DefenseAgent limit: return at most 3 code_evidence items and at most 3 defense_evidence items. "
            "Start with JSON immediately."
            if task.assigned_agent == "DefenseAgent"
            else ""
        )
        user_prompt = build_agent_user_prompt(
            sample,
            task,
            plan,
            agent_code_char_limit,
            role_extra=role_extra,
        )
        agent_conversations.append([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ])
        valid_task_items.append((sample, task, warnings))

    agent_outputs = llm_chat(llm, agent_conversations, sampling_params=sampling_json, use_tqdm=True) if agent_conversations else []
    for idx, out in enumerate(agent_outputs):
        sample, task, warnings = valid_task_items[idx]
        result = results[sample.sample_id]
        raw_text = out.outputs[0].text
        try:
            report = offline.parse_json_output(raw_text, AgentVerificationReport)
            validate_agent_report_shape(report)
            report.agent_name = task.assigned_agent
            report.task_id = task.task_id
            report.hypothesis_id = task.hypothesis_id
            report.target_cwe = task.target_cwe
            report.graph_evidence = warnings
            report.raw_output = raw_text
            report.parse_error = ""
        except Exception as exc:
            logger.warning(f"{sample.sample_id}/{task.task_id} JSON parse failed or incomplete; using NL fallback: {exc}")
            report = natural_language_agent_fallback(raw_text, task, warnings, exc)
        report_set(report, "verification_round", 1)
        normalized_report = normalize_agent_report_semantics(report)
        report_slots[(sample.sample_id, task.task_id)] = len(result.agent_reports)
        result.agent_reports.append(normalized_report)

    logger.info("[STAGE 6B/7] External retrieval disabled for without-KG ablation")

    logger.info("[STAGE 7/7] Final Judge with global and local evidence...")
    fusion_conversations = []
    valid_fusion_samples = []
    for sample in pending_samples:
        result = results[sample.sample_id]
        plan = result.orchestrator_plan
        if result.status == "error" or not plan:
            continue
        cwe_candidates = collect_cwe_candidates(plan)
        user_prompt = "\n\n".join(
            [
                "Code-only global risk assessment (coarse independent opinion):",
                result.global_risk_assessment.model_dump_json(indent=2)
                if result.global_risk_assessment
                else "No global risk assessment available",
                "Global preliminary diagnosis and fallback CWE:",
                result.global_preliminary_diagnosis.model_dump_json(indent=2)
                if result.global_preliminary_diagnosis
                else "No global preliminary diagnosis available",
                "Orchestrator plan:",
                plan.model_dump_json(indent=2),
                "Candidate CWE pool:",
                ", ".join(cwe_candidates) if cwe_candidates else "No recommended candidates",
                "Agent reports:",
                agent_reports_to_text(result.agent_reports, max_chars=7000),
                f"C/C++ source code:\n```cpp\n{normalize_code(sample.code, agent_fusion_code_char_limit)}\n```",
                "Do not output <think>. Output pure JSON only. The first character must be '{'.",
            ]
        )
        fusion_conversations.append([
            {"role": "system", "content": FINAL_JUDGE_SYSTEM},
            {"role": "user", "content": user_prompt},
        ])
        valid_fusion_samples.append(sample)

    fusion_outputs = llm_chat(llm, fusion_conversations, sampling_params=sampling_report, use_tqdm=True) if fusion_conversations else []
    for idx, out in enumerate(fusion_outputs):
        sample = valid_fusion_samples[idx]
        result = results[sample.sample_id]
        raw_text = out.outputs[0].text
        result.raw_fusion_output = raw_text
        try:
            decision = offline.parse_json_output(raw_text, AgentFusionDecision)
        except Exception as exc:
            logger.error(f"{sample.sample_id} final fusion parse failed; conservative fallback: {exc}")
            verifier_reports = [r for r in result.agent_reports if r.agent_name != "DefenseAgent"]
            supported_reports = [r for r in verifier_reports if r.verdict == "supported"]
            strong_supported = [r for r in supported_reports if _has_concrete_dangerous_evidence(r)]
            high_supported = [r for r in strong_supported if r.confidence >= 0.9]
            defense_blocks = [
                r for r in result.agent_reports
                if r.agent_name == "DefenseAgent" and _defense_overlaps_supported_risk(r, supported_reports)
            ]
            global_risk = result.global_risk_assessment
            is_vulnerable = (
                len(strong_supported) >= 2
                or bool(high_supported)
                or (bool(strong_supported) and not bool(defense_blocks))
            )
            cwe_id = _supported_cwe(strong_supported or high_supported or supported_reports)
            decision = AgentFusionDecision(
                fusion_trace=(
                    f"Fallback fusion. supported={len(supported_reports)}, "
                    f"strong_supported={len(strong_supported)}, "
                    f"high_supported={len(high_supported)}, "
                    f"overlap_defense_blocks={len(defense_blocks)}, "
                    f"global_risk={global_risk.is_vulnerable if global_risk else 'N/A'}, "
                    f"global_confidence={global_risk.confidence if global_risk else 'N/A'}"
                ),
                is_vulnerable=is_vulnerable,
                confidence=0.65 if is_vulnerable else 0.5,
                cwe_id=cwe_id if is_vulnerable else "",
                vulnerability_type="Fallback multi-agent decision" if is_vulnerable else "",
                explanation="最终裁决JSON解析失败，系统根据子智能体支持与反证数量进行了保守融合。",
                affected_lines=[],
            )

        enforced = enforce_final_decision(
            result.global_risk_assessment,
            result.global_preliminary_diagnosis,
            result.agent_reports,
            decision,
        )
        decision = enforced.decision
        result.binary_source = enforced.binary_source
        result.cwe_source = enforced.cwe_source
        result.proposed_binary = enforced.proposed_binary
        result.proposed_cwe = enforced.proposed_cwe
        result.overridden_fields = enforced.overridden_fields
        result.final_fusion_trace = decision.fusion_trace
        global_risk = result.global_risk_assessment
        global_critique = global_risk.graph_warning_critique if global_risk else ""
        global_logic = global_risk.code_logic_analysis if global_risk else ""
        result.diagnosis = DiagnosisResult(
            graph_warning_critique=truncate_middle(
                "\n\n".join(
                    part for part in [global_critique, agent_reports_to_text(result.agent_reports)] if part
                ),
                4000,
                "global and agent critique",
            ),
            code_logic_analysis=truncate_middle(
                "\n\n".join(part for part in [global_logic, decision.fusion_trace] if part),
                4000,
                "global and final logic",
            ),
            is_vulnerable=decision.is_vulnerable,
            confidence=decision.confidence,
            cwe_id=decision.cwe_id if decision.is_vulnerable else "",
            vulnerability_type=decision.vulnerability_type if decision.is_vulnerable else "",
            explanation=decision.explanation,
            affected_lines=decision.affected_lines,
        )
        result.status = "success"
        result.assembled_prompt_preview = (
            f"Unified code-only multi-agent ablation. "
            f"Global={global_risk.is_vulnerable if global_risk else 'N/A'}; "
            f"Plan={result.orchestrator_plan.initial_risk_assessment if result.orchestrator_plan else 'N/A'}; "
            f"reports={len(result.agent_reports)}; graph_warnings={len(result.graph_warnings)}"
        )

    final_results: dict[str, AgentDetectionResult] = {}
    final_results.update(existing)
    final_results.update(results)

    ordered_records = []
    for sample in samples:
        if sample.sample_id in final_results:
            ordered_records.append(json.loads(final_results[sample.sample_id].model_dump_json()))

    output_path.write_text(json.dumps(ordered_records, ensure_ascii=False, indent=2), encoding="utf-8")
    elapsed = time.time() - start
    success_count = sum(1 for r in results.values() if r.status == "success")
    error_count = sum(1 for r in results.values() if r.status == "error")
    logger.info(
        f"Multi-agent offline experiment complete | success={success_count} error={error_count} "
        f"elapsed={elapsed:.1f}s output={output_path}"
    )


if __name__ == "__main__":
    main()
