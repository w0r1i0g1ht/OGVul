# -*- coding: utf-8 -*-
"""
Multi-agent KG-RAG vulnerability detection entrypoint.

This script uses vLLM Native Engine offline inference directly. It does not
start or call the OpenAI-compatible vLLM API server.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import random
import re
import sys
import time
from pathlib import Path

import yaml
from neo4j import GraphDatabase

import main_offline as offline
from agent_schemas import (
    AgentDetectionResult,
    AgentFusionDecision,
    AgentTask,
    AgentVerificationReport,
    OrchestratorPlan,
)
from data_loader import DataLoader
from schemas import DiagnosisResult, GraphWarning, TypedEntity


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
logger = logging.getLogger("agent_kg_vuln_detect_offline")


ORCHESTRATOR_SYSTEM = (
    "You are the Orchestrator Agent for a multi-agent vulnerability detection system "
    "for Oil & Gas industrial C/C++ software.\n"
    "Your job is NOT to make the final verdict yet. Generate concrete, verifiable "
    "vulnerability hypotheses for downstream agents.\n\n"
    "Requirements:\n"
    "1. Extract 3-5 important entities. Each entity has name, type, importance. "
    "type must be one of: Protocol, Variable, FunctionCall, System, Asset. "
    "importance must be one of: High, Medium, Low.\n"
    "2. Write a short English semantic_summary without discussing safety checks.\n"
    "3. Classify domain as one of: Protocol, Simulation, Database, System, Other.\n"
    "4. Provide 1-4 context_possible_cwes.\n"
    "5. Generate 1-3 concrete vulnerability_hypotheses. Each hypothesis must be "
    "testable against code evidence. Use assigned_agent='VulnerabilityVerifier'.\n"
    "6. Do not propose CWE-476 only because code checks pointer == NULL. CWE-476 "
    "requires an actual dereference such as *ptr, ptr->field, ptr[index], or a call "
    "that dereferences a possibly NULL pointer.\n"
    "7. initial_risk_assessment must be one of: safe, suspicious, vulnerable, uncertain.\n\n"
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
    "1. A Knowledge Graph warning is only a clue, not a verdict.\n"
    "2. The graph field verification_contract is a checklist for what to verify; it is NOT "
    "evidence that the current code already has a defense.\n"
    "3. Mark verdict='supported' only if a concrete dangerous operation remains undefended "
    "in the source code.\n"
    "4. Mark verdict='not_supported' if the source code has sufficient checks or the graph "
    "warning is irrelevant.\n"
    "5. Mark verdict='uncertain' if evidence is insufficient.\n"
    "6. Focus only on the assigned task; do not make the final global decision.\n\n"
    "CWE-476 rule: a NULL check such as ptr == NULL is not a NULL-dereference vulnerability. "
    "Only support CWE-476 when the code dereferences a possibly NULL pointer through *ptr, "
    "ptr->field, ptr[index], or an equivalent call without a prior dominating NULL guard.\n\n"
    "Do not output <think> or reasoning text. The first character of your response must be '{'. "
    "Output ONLY a pure JSON object with fields: agent_name, task_id, hypothesis_id, target_cwe, "
    "code_evidence, defense_evidence, verdict, confidence, recommended_cwe, summary, retrieval_request.\n"
    "target_cwe and recommended_cwe must be single strings. code_evidence and defense_evidence "
    "must be arrays of objects: {\"evidence_type\": \"dangerous_operation|missing_check|defense|neutral\", "
    "\"line_or_snippet\": \"exact source snippet\", \"analysis\": \"why it matters\"}. "
    "If verdict='uncertain' or evidence is weak, set retrieval_request to one concise KG search query "
    "describing the missing CWE, API, variable, source, sink, or defense knowledge needed for a second pass. "
    "If no more KG context is needed, set retrieval_request to an empty string.\n"
    "Do not put graph mitigation text into defense_evidence unless the source code actually implements it.\n"
    "Do not include markdown."
)


DEFENSE_SYSTEM = (
    "You are the Defense Agent. Your role is to find safety defenses and counter-evidence "
    "that may refute vulnerability hypotheses in the given C/C++ code.\n\n"
    "Look for explicit bounds checks, input validation, safe APIs, RAII/smart pointer lifecycle "
    "management, lock protection, error-path cleanup, and other defenses.\n"
    "The graph field verification_contract is only a checklist of recommended mitigations. "
    "It is NOT proof that this source code has those defenses.\n"
    "For CWE-476, NULL checks are defense evidence. They are not vulnerability evidence unless "
    "the code later dereferences the same pointer without a dominating guard.\n"
    "If a graph warning is fully defended or irrelevant, say so clearly.\n\n"
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
    "You are the Final Judge Agent for a multi-agent KG-RAG vulnerability detection system.\n"
    "Fuse the Orchestrator plan, Knowledge Graph warnings, Vulnerability Verifier reports, "
    "and Defense Agent report into one final decision.\n\n"
    "Decision rules:\n"
    "1. Do NOT classify as vulnerable based only on graph warnings.\n"
    "2. Graph verification_contract text is only a checklist, not proof of implemented defenses.\n"
    "3. At least one concrete dangerous operation must remain undefended for is_vulnerable=true.\n"
    "4. If the Defense Agent shows a source-code-specific sufficient defense, downgrade or reject the risk.\n"
    "5. Code evidence is stronger than graph evidence.\n"
    "6. Do not accept CWE-476 unless there is an actual dereference of a possibly NULL pointer; "
    "NULL checks alone are defense evidence, not vulnerability evidence.\n"
    "7. Do not mark vulnerable when the only support is hypothetical wording such as may/could/potential, "
    "missing context, or a generic missing-check claim without a concrete sink/source operation.\n"
    "8. If most verifier reports are not_supported or uncertain, and DefenseAgent reports specific checks, "
    "return is_vulnerable=false or confidence<=0.5.\n"
    "9. If vulnerable, choose the CWE that best represents the code root cause.\n"
    "10. The explanation field must be concise Chinese.\n\n"
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


def graph_warnings_to_text(
    warnings: list[GraphWarning],
    include_cwe: bool = True,
    max_items: int = 10,
    max_chars: int = 6000,
) -> str:
    if not warnings:
        return "No graph warnings retrieved for this task."
    lines = []
    for idx, warning in enumerate(warnings[:max_items], 1):
        warn_text = truncate_middle(offline.sanitize_cwe_text(warning.warning), 600, "graph warning")
        contract = truncate_middle(
            offline.sanitize_cwe_text(warning.verification_contract),
            800,
            "verification contract",
        )
        cwe = f" | CWE: {warning.cwe_id}" if include_cwe and warning.cwe_id else ""
        contract_text = f"\n   Verification Contract: {contract}" if contract else ""
        lines.append(f"{idx}. Entity: {warning.entity}{cwe}\n   Warning: {warn_text}{contract_text}")
    if len(warnings) > max_items:
        lines.append(f"... {len(warnings) - max_items} additional graph warnings omitted ...")
    return truncate_middle("\n".join(lines), max_chars, "graph warnings")


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
    warnings: list[GraphWarning],
    code_char_limit: int,
    role_extra: str = "",
    previous_report: AgentVerificationReport | None = None,
) -> str:
    round_extra = ""
    if previous_report:
        round_extra = "\n\n".join(
            [
                "Second-pass verification:",
                "The previous report was inconclusive or weak. Re-check the same task using the supplemental graph evidence.",
                f"Previous verdict: {previous_report.verdict}",
                f"Previous confidence: {previous_report.confidence}",
                f"Previous summary: {previous_report.summary}",
                f"Previous retrieval_request: {report_get(previous_report, 'retrieval_request', '')}",
                "If the supplemental evidence still does not connect to concrete source-code evidence, keep verdict='uncertain' or 'not_supported'.",
            ]
        )
    return "\n\n".join(
        [
            f"Task ID: {task.task_id}",
            f"Hypothesis ID: {task.hypothesis_id}",
            f"Assigned role: {task.assigned_agent}",
            f"Target CWE: {task.target_cwe or 'None'}",
            f"Risk type: {task.risk_type or 'General'}",
            f"Task goal: {task.task_goal}",
            f"Orchestrator semantic summary: {plan.semantic_summary}",
            f"Graph evidence retrieved for this task:\n{graph_warnings_to_text(warnings, include_cwe=True)}",
            round_extra,
            "Important: graph verification_contract text is a verification checklist only. "
            "It must not be copied into defense_evidence unless the source code below actually implements it.",
            "Important for CWE-476: pointer NULL checks are not vulnerability evidence. "
            "Only an actual dereference of a possibly NULL pointer supports CWE-476.",
            role_extra,
            f"C/C++ source code:\n```cpp\n{normalize_code(sample.code, code_char_limit)}\n```",
            "Return code_evidence and defense_evidence as arrays of objects, never as strings. "
            "Do not output <think>. Output pure JSON only. The first character must be '{'.",
        ]
    )


def build_candidate_index(driver, db_name: str) -> tuple[list[str], dict[str, float]]:
    logger.info("Loading candidate graph nodes from Neo4j...")
    with driver.session(database=db_name) as session:
        result = session.run("MATCH (n:OGL_Node) RETURN distinct n.name as name")
        candidate_nodes = [record["name"] for record in result if record["name"]]

    word_doc_counts: dict[str, int] = {}
    for name in candidate_nodes:
        tokens = [w for w in re.split(r"[^a-zA-Z0-9]", name.lower()) if w]
        sig_tokens = {t for t in tokens if t not in offline.NOISE_WORDS and len(t) > 2}
        for token in sig_tokens:
            word_doc_counts[token] = word_doc_counts.get(token, 0) + 1

    corpus_size = len(candidate_nodes)
    node_idf = {
        word: math.log((corpus_size - count + 0.5) / (count + 0.5) + 1)
        for word, count in word_doc_counts.items()
    }
    logger.info(f"Candidate nodes={len(candidate_nodes)}, IDF vocab={len(node_idf)}")
    return candidate_nodes, node_idf


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


def collect_cwe_candidates(plan: OrchestratorPlan, warnings: list[GraphWarning]) -> list[str]:
    cwes = set()
    for cwe in plan.context_possible_cwes:
        match = re.search(r"(?i)cwe[-_]?\d+", cwe or "")
        if match:
            digits = re.search(r"\d+", match.group(0))
            if digits:
                cwes.add(f"CWE-{digits.group(0)}")
    for warning in warnings:
        match = re.search(r"(?i)cwe[-_]?\d+", warning.cwe_id or "")
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


def llm_chat(llm, conversations, sampling_params, use_tqdm: bool = True):
    try:
        return llm.chat(
            conversations,
            sampling_params=sampling_params,
            use_tqdm=use_tqdm,
            chat_template_kwargs={"enable_thinking": False},
        )
    except TypeError:
        logger.warning("Current vLLM does not support chat_template_kwargs.enable_thinking; falling back.")
        return llm.chat(conversations, sampling_params=sampling_params, use_tqdm=use_tqdm)


def result_filename(config: dict) -> str:
    mode = config.get("experiment", {}).get("pipeline_mode", "kg_rag")
    return f"detection_results_agent_{mode}.json"


def load_existing_results(path: Path) -> dict[str, AgentDetectionResult]:
    if not path.exists():
        return {}
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
        loaded: dict[str, AgentDetectionResult] = {}
        for record in records:
            if not record.get("raw_orchestrator_output") or not record.get("raw_fusion_output"):
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


def apply_final_decision_guard(
    decision: AgentFusionDecision,
    reports: list[AgentVerificationReport],
) -> AgentFusionDecision:
    """Downgrade only when support is weak and a matching concrete defense exists."""
    if not decision.is_vulnerable:
        return decision

    verifier_reports = [r for r in reports if r.agent_name != "DefenseAgent"]
    supported_reports = [r for r in verifier_reports if r.verdict == "supported"]
    strong_supported = [r for r in supported_reports if _has_concrete_dangerous_evidence(r)]
    high_supported = [r for r in strong_supported if r.confidence >= 0.9]
    defense_reports = [r for r in reports if r.agent_name == "DefenseAgent"]
    overlapping_defense = any(_defense_overlaps_supported_risk(r, supported_reports) for r in defense_reports)

    should_downgrade = False
    reasons = []
    if len(strong_supported) >= 2 or high_supported:
        return decision
    if not supported_reports:
        should_downgrade = True
        reasons.append("no verifier-supported vulnerability evidence")
    elif not strong_supported:
        average_confidence = sum(r.confidence for r in supported_reports) / len(supported_reports)
        if len(supported_reports) >= 2 and average_confidence >= 0.85 and not overlapping_defense:
            return decision
        should_downgrade = True
        reasons.append("support lacks concrete dangerous operation evidence")
    elif len(supported_reports) == 1 and overlapping_defense and supported_reports[0].confidence < 0.85:
        should_downgrade = True
        reasons.append("single low-confidence support is refuted by matching defense")

    if not should_downgrade:
        return decision

    decision.fusion_trace = (
        decision.fusion_trace
        + " | Guard downgrade: "
        + "; ".join(reasons)
    )
    decision.is_vulnerable = False
    decision.confidence = min(decision.confidence, 0.5)
    decision.cwe_id = ""
    decision.vulnerability_type = ""
    decision.explanation = (
        "证据主要为假设性风险或缺少足够具体的未防御危险操作，"
        "系统按保守策略降级为未确认漏洞。"
    )
    decision.affected_lines = []
    return decision


def merge_graph_warnings(*warning_groups: list[GraphWarning]) -> list[GraphWarning]:
    seen = set()
    merged: list[GraphWarning] = []
    for warnings in warning_groups:
        for warning in warnings:
            key = (warning.entity, warning.warning, warning.cwe_id, warning.verification_contract)
            if key in seen:
                continue
            seen.add(key)
            merged.append(warning)
    return merged


def fallback_retrieval_request(task: AgentTask, report: AgentVerificationReport) -> str:
    parts = [
        task.target_cwe,
        task.risk_type,
        task.task_goal,
        report.recommended_cwe,
        report.summary,
    ]
    return truncate_middle(" ".join(part for part in parts if part), 500, "retrieval request")


def needs_second_pass(task: AgentTask, report: AgentVerificationReport) -> bool:
    if task.assigned_agent != "VulnerabilityVerifier":
        return False
    if report_get(report, "verification_round", 1) >= 2:
        return False
    if not report.graph_evidence and report.verdict != "not_supported":
        return True
    if report.confidence < 0.65:
        return True
    if report.verdict == "uncertain":
        return True
    return False


def second_pass_priority(task: AgentTask, report: AgentVerificationReport) -> tuple[int, float]:
    if task.assigned_agent != "VulnerabilityVerifier":
        return (0, 0.0)
    if not report.graph_evidence and report.verdict != "not_supported":
        return (4, 1.0 - report.confidence)
    if report.confidence < 0.65:
        return (3, 1.0 - report.confidence)
    if report.verdict == "uncertain":
        return (2, 1.0 - report.confidence)
    return (1, 0.0)


def choose_second_pass_report(
    previous_report: AgentVerificationReport,
    second_report: AgentVerificationReport,
) -> AgentVerificationReport:
    previous_strong = previous_report.verdict == "supported" and _has_concrete_dangerous_evidence(previous_report)
    second_strong = second_report.verdict == "supported" and _has_concrete_dangerous_evidence(second_report)

    if previous_strong:
        if second_strong and second_report.confidence >= previous_report.confidence:
            return second_report
        return previous_report

    if second_strong:
        return second_report

    if previous_report.verdict == "supported" and second_report.verdict != "supported":
        return previous_report

    if previous_report.verdict != "supported" and second_report.verdict == "supported":
        return second_report if second_report.confidence >= 0.75 else previous_report

    if second_report.verdict == previous_report.verdict and second_report.confidence > previous_report.confidence + 0.1:
        return second_report

    return previous_report


def second_pass_entities(task: AgentTask, plan: OrchestratorPlan, request: str) -> list[TypedEntity]:
    entities = list(task.entities or plan.entities)
    clean_request = re.sub(r"\s+", " ", request or "").strip()
    if clean_request:
        entities.append(
            TypedEntity(
                name=truncate_middle(clean_request, 240, "retrieval request"),
                type="FunctionCall",
                importance="High",
            )
        )
    return entities


def second_pass_cwes(task: AgentTask, plan: OrchestratorPlan, report: AgentVerificationReport) -> list[str]:
    cwes: list[str] = []
    for text in [task.target_cwe, report.recommended_cwe, report_get(report, "retrieval_request", ""), report.summary]:
        cwes.extend(re.findall(r"(?i)cwe[-_]?\d+", text or ""))
    if not cwes:
        cwes.extend(plan.context_possible_cwes)
    return cwes


def query_second_pass_warnings(
    driver,
    db_name: str,
    candidate_nodes: list[str],
    node_idf: dict[str, float],
    task: AgentTask,
    plan: OrchestratorPlan,
    report: AgentVerificationReport,
) -> list[GraphWarning]:
    request = report_get(report, "retrieval_request", "") or fallback_retrieval_request(task, report)
    if not request:
        return []
    semantic_summary = " ".join([plan.semantic_summary, task.task_goal, request])
    retrieval_kwargs = dict(
        max_matched_nodes=8,
        max_warnings_per_node=6,
        score_cutoff_ratio=0.30,
        min_score_cutoff=0.30,
        semantic_threshold_bge=0.25,
        semantic_threshold_tfidf=0.02,
        cwe_filter_mode="soft",
        max_cwe_types=6,
        rewrite_non_exact=True,
    )
    cwes = second_pass_cwes(task, plan, report)
    warnings = offline.query_graph_warnings(
        driver,
        db_name,
        candidate_nodes,
        node_idf,
        second_pass_entities(task, plan, request),
        semantic_summary,
        task.domain or plan.domain,
        context_possible_cwes=cwes,
        **retrieval_kwargs,
    )
    if warnings:
        return warnings
    return offline.query_graph_warnings(
        driver,
        db_name,
        candidate_nodes,
        node_idf,
        second_pass_entities(task, plan, request),
        semantic_summary,
        task.domain or plan.domain,
        context_possible_cwes=[],
        **{**retrieval_kwargs, "cwe_filter_mode": "none"},
    )


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
    parser = argparse.ArgumentParser(description="Multi-agent KG-RAG vulnerability detection with offline vLLM")
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
    agent_fusion_code_char_limit = int(runtime_conf.get("agent_fusion_code_char_limit", 8000))
    agent_second_pass_enabled_value = runtime_conf.get("agent_second_pass_enabled", True)
    agent_second_pass_enabled = str(agent_second_pass_enabled_value).strip().lower() not in {"0", "false", "no", "off"}
    agent_second_pass_max_tasks = int(runtime_conf.get("agent_second_pass_max_tasks", 0))
    agent_second_pass_max_per_sample = int(runtime_conf.get("agent_second_pass_max_per_sample", 1))

    output_dir = Path(config["paths"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / result_filename(config)

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
    sampling_json = offline.SamplingParams(max_tokens=2048, temperature=0.0)
    sampling_report = offline.SamplingParams(max_tokens=min(2048, llm_conf.get("max_tokens", 4096)), temperature=0.1)

    neo4j_conf = config["neo4j"]
    driver = GraphDatabase.driver(
        neo4j_conf["uri"],
        auth=(neo4j_conf["username"], neo4j_conf["password"]),
    )
    db_name = neo4j_conf.get("database", "neo4j")
    candidate_nodes, node_idf = build_candidate_index(driver, db_name)

    results = {sample.sample_id: build_result(sample, mode) for sample in pending_samples}

    logger.info("[STAGE 1/4] Orchestrator planning...")
    orch_conversations = []
    for sample in pending_samples:
        user_prompt = "\n\n".join(
            [
                f"Sample ID: {sample.sample_id}",
                f"Ground-truth label is hidden from you. Source type: {sample.source_type}",
                f"C/C++ source code:\n```cpp\n{normalize_code(sample.code, agent_code_char_limit)}\n```",
                "Output only JSON. Do not output <think>. The first character must be '{'.",
            ]
        )
        orch_conversations.append([
            {"role": "system", "content": ORCHESTRATOR_SYSTEM},
            {"role": "user", "content": user_prompt},
        ])

    orch_outputs = llm_chat(llm, orch_conversations, sampling_params=sampling_json, use_tqdm=True)
    for idx, out in enumerate(orch_outputs):
        sample = pending_samples[idx]
        result = results[sample.sample_id]
        raw_text = out.outputs[0].text
        result.raw_orchestrator_output = raw_text
        try:
            plan = offline.parse_json_output(raw_text, OrchestratorPlan)
            result.orchestrator_plan = plan
            result.agent_tasks = make_tasks(plan)
        except Exception as exc:
            logger.error(f"{sample.sample_id} orchestrator parse failed: {exc}")
            result.status = "error"
            result.error_message = f"orchestrator parse failed: {exc}"

    logger.info("[STAGE 2/4] Task-scoped graph retrieval...")
    task_items = []
    task_warnings: dict[tuple[str, str], list[GraphWarning]] = {}
    for sample in pending_samples:
        result = results[sample.sample_id]
        plan = result.orchestrator_plan
        if result.status == "error" or not plan:
            continue
        all_warnings: list[GraphWarning] = []
        for task in result.agent_tasks:
            task_cwes = re.findall(r"(?i)cwe[-_]?\d+", task.target_cwe or "")
            if task.assigned_agent == "DefenseAgent":
                retrieval_kwargs = dict(
                    max_matched_nodes=8,
                    max_warnings_per_node=6,
                    score_cutoff_ratio=0.35,
                    min_score_cutoff=0.35,
                    semantic_threshold_bge=0.30,
                    semantic_threshold_tfidf=0.03,
                    cwe_filter_mode="none",
                    max_cwe_types=6,
                    rewrite_non_exact=True,
                )
                cwes = []
            else:
                retrieval_kwargs = dict(
                    max_matched_nodes=6,
                    max_warnings_per_node=5,
                    score_cutoff_ratio=0.45,
                    min_score_cutoff=0.45,
                    semantic_threshold_bge=0.38,
                    semantic_threshold_tfidf=0.05,
                    cwe_filter_mode="soft",
                    max_cwe_types=4,
                    rewrite_non_exact=True,
                )
                cwes = task_cwes or plan.context_possible_cwes

            warnings = offline.query_graph_warnings(
                driver,
                db_name,
                candidate_nodes,
                node_idf,
                task.entities or plan.entities,
                plan.semantic_summary,
                task.domain or plan.domain,
                context_possible_cwes=cwes,
                **retrieval_kwargs,
            )
            if not warnings:
                warnings = offline.query_graph_warnings(
                    driver,
                    db_name,
                    candidate_nodes,
                    node_idf,
                    task.entities or plan.entities,
                    plan.semantic_summary,
                    task.domain or plan.domain,
                    context_possible_cwes=[],
                    **{**retrieval_kwargs, "cwe_filter_mode": "none"},
                )
            task_warnings[(sample.sample_id, task.task_id)] = warnings
            all_warnings.extend(warnings)
            task_items.append((sample, task))

        seen = set()
        unique_warnings = []
        for warning in all_warnings:
            key = (warning.entity, warning.warning, warning.cwe_id)
            if key not in seen:
                seen.add(key)
                unique_warnings.append(warning)
        result.graph_warnings = unique_warnings

    logger.info("[STAGE 3/4] Verifier and Defense agents...")
    agent_conversations = []
    valid_task_items = []
    report_slots: dict[tuple[str, str], int] = {}
    for sample, task in task_items:
        result = results[sample.sample_id]
        plan = result.orchestrator_plan
        if not plan:
            continue
        warnings = task_warnings.get((sample.sample_id, task.task_id), [])
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
            warnings,
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

    second_pass_items = []
    if agent_second_pass_enabled:
        for sample, task, warnings in valid_task_items:
            result = results[sample.sample_id]
            slot = report_slots.get((sample.sample_id, task.task_id))
            if slot is None:
                continue
            report = result.agent_reports[slot]
            if not needs_second_pass(task, report):
                continue
            if not report_get(report, "retrieval_request", ""):
                report_set(report, "retrieval_request", fallback_retrieval_request(task, report))
            second_pass_items.append((sample, task, warnings, report))
        if agent_second_pass_max_per_sample > 0:
            selected_by_sample: dict[str, list] = {}
            for item in sorted(
                second_pass_items,
                key=lambda item: second_pass_priority(item[1], item[3]),
                reverse=True,
            ):
                sample_id = item[0].sample_id
                selected_by_sample.setdefault(sample_id, [])
                if len(selected_by_sample[sample_id]) < agent_second_pass_max_per_sample:
                    selected_by_sample[sample_id].append(item)
            second_pass_items = [
                item
                for sample_items in selected_by_sample.values()
                for item in sample_items
            ]
        if agent_second_pass_max_tasks > 0:
            second_pass_items = second_pass_items[:agent_second_pass_max_tasks]

    logger.info(f"[STAGE 3B/4] Second-pass KG retrieval and verifier review... tasks={len(second_pass_items)}")
    second_conversations = []
    second_valid_items = []
    for sample, task, old_warnings, previous_report in second_pass_items:
        result = results[sample.sample_id]
        plan = result.orchestrator_plan
        if not plan:
            continue
        supplemental_warnings = query_second_pass_warnings(
            driver,
            db_name,
            candidate_nodes,
            node_idf,
            task,
            plan,
            previous_report,
        )
        if not supplemental_warnings:
            logger.info(f"{sample.sample_id}/{task.task_id} second-pass retrieval returned no new warnings")
            continue
        merged_warnings = merge_graph_warnings(old_warnings, supplemental_warnings)
        task_warnings[(sample.sample_id, task.task_id)] = merged_warnings
        result.graph_warnings = merge_graph_warnings(result.graph_warnings, supplemental_warnings)
        user_prompt = build_agent_user_prompt(
            sample,
            task,
            plan,
            merged_warnings,
            agent_code_char_limit,
            previous_report=previous_report,
        )
        second_conversations.append([
            {"role": "system", "content": VERIFIER_SYSTEM},
            {"role": "user", "content": user_prompt},
        ])
        second_valid_items.append((sample, task, merged_warnings, previous_report))

    second_outputs = llm_chat(llm, second_conversations, sampling_params=sampling_json, use_tqdm=True) if second_conversations else []
    for idx, out in enumerate(second_outputs):
        sample, task, warnings, previous_report = second_valid_items[idx]
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
            logger.warning(f"{sample.sample_id}/{task.task_id} second-pass JSON parse failed; keeping NL fallback: {exc}")
            report = natural_language_agent_fallback(raw_text, task, warnings, exc)
        report_set(report, "verification_round", 2)
        report_set(report, "previous_verdict", previous_report.verdict)
        report_set(report, "previous_summary", previous_report.summary)
        if not report_get(report, "retrieval_request", ""):
            report_set(report, "retrieval_request", report_get(previous_report, "retrieval_request", ""))
        normalized_report = normalize_agent_report_semantics(report)
        slot = report_slots.get((sample.sample_id, task.task_id))
        if slot is not None:
            result.agent_reports[slot] = choose_second_pass_report(previous_report, normalized_report)

    logger.info("[STAGE 4/4] Final fusion...")
    fusion_conversations = []
    valid_fusion_samples = []
    for sample in pending_samples:
        result = results[sample.sample_id]
        plan = result.orchestrator_plan
        if result.status == "error" or not plan:
            continue
        cwe_candidates = collect_cwe_candidates(plan, result.graph_warnings)
        user_prompt = "\n\n".join(
            [
                "Orchestrator plan:",
                plan.model_dump_json(indent=2),
                "Candidate CWE pool:",
                ", ".join(cwe_candidates) if cwe_candidates else "No recommended candidates",
                "All retrieved graph warnings:",
                graph_warnings_to_text(result.graph_warnings, include_cwe=True, max_items=12, max_chars=7000),
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
                    f"overlap_defense_blocks={len(defense_blocks)}"
                ),
                is_vulnerable=is_vulnerable,
                confidence=0.65 if is_vulnerable else 0.5,
                cwe_id=cwe_id if is_vulnerable else "",
                vulnerability_type="Fallback multi-agent decision" if is_vulnerable else "",
                explanation="最终裁决JSON解析失败，系统根据子智能体支持与反证数量进行了保守融合。",
                affected_lines=[],
            )

        decision = apply_final_decision_guard(decision, result.agent_reports)
        result.final_fusion_trace = decision.fusion_trace
        result.diagnosis = DiagnosisResult(
            graph_warning_critique=agent_reports_to_text(result.agent_reports)[:4000],
            code_logic_analysis=decision.fusion_trace,
            is_vulnerable=decision.is_vulnerable,
            confidence=decision.confidence,
            cwe_id=decision.cwe_id if decision.is_vulnerable else "",
            vulnerability_type=decision.vulnerability_type if decision.is_vulnerable else "",
            explanation=decision.explanation,
            affected_lines=decision.affected_lines,
        )
        result.status = "success"
        result.assembled_prompt_preview = (
            f"Multi-agent KG-RAG. Plan={result.orchestrator_plan.initial_risk_assessment if result.orchestrator_plan else 'N/A'}; "
            f"reports={len(result.agent_reports)}; graph_warnings={len(result.graph_warnings)}"
        )

    driver.close()

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
