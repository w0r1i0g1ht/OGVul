"""Refine CWE attribution while keeping every Hybrid binary verdict immutable."""

from __future__ import annotations

import argparse
import copy
import csv
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import yaml

import evaluate


ROOT = Path(__file__).resolve().parent
AGENT_DIR = ROOT / "agent"
DEFAULT_INPUT = ROOT / "outputs" / "hybrid" / "detection_results_hybrid_kg_agent.json"
DEFAULT_OUTPUT_DIR = ROOT / "outputs" / "hybrid_cwe_refined"
DEFAULT_CONFIG = AGENT_DIR / "config.yaml"

CWE_PATTERN = re.compile(r"(?i)cwe[-_\s]*(\d+)")
CHECKPOINT_VERSION = 2
PAIRWISE_CHECKPOINT_VERSION = 1

SYSTEM_PROMPT = (
    "You are a candidate-specific CWE evidence verifier for source-code vulnerability attribution. "
    "The binary vulnerability verdict is already frozen and MUST NOT be reconsidered. "
    "Evaluate only whether the supplied candidate CWE is the specific root cause of the shown code.\n\n"
    "Rules:\n"
    "1. Infer the source language first, then inspect the code independently. Candidate provenance is only a clue, not evidence.\n"
    "2. Distinguish sibling mechanisms precisely, especially read vs write, stack vs heap, "
    "double-free vs use-after-free, integer error vs downstream memory corruption, and root cause vs consequence.\n"
    "3. mechanism_supported=true requires a concrete dangerous operation and an absent or insufficient defense.\n"
    "4. dangerous_operation must quote an exact source snippet. Use an empty string if none exists.\n"
    "5. Scores are numbers from 0.0 to 1.0. Do not compare this candidate with other candidates.\n"
    "6. Output pure JSON only, with fields: candidate_cwe, mechanism_supported, dangerous_operation, "
    "root_cause_fit, evidence_strength, specificity, confidence, reason."
)

PAIRWISE_SYSTEM_PROMPT = (
    "You are a conservative pairwise CWE adjudicator for source-code vulnerability attribution. "
    "The binary vulnerability verdict is frozen and MUST NOT be reconsidered. Compare exactly two CWE labels: "
    "the current label and one challenger.\n\n"
    "Rules:\n"
    "1. Infer the source language before reasoning about APIs, memory behavior, or defenses.\n"
    "2. Decide the specific root cause, not a downstream consequence or a merely plausible weakness.\n"
    "3. Prefer the current CWE unless the code provides concrete evidence that refutes it and supports the challenger.\n"
    "4. A challenger can win only when challenger_evidence quotes an exact dangerous operation from the source.\n"
    "5. If both labels are plausible, both are wrong, or evidence is insufficient, choose undetermined.\n"
    "6. Do not introduce a third CWE and do not reconsider is_vulnerable.\n"
    "7. Output pure JSON only with fields: code_language, current_cwe, challenger_cwe, preferred, "
    "current_refuted, challenger_supported, current_refutation, challenger_evidence, "
    "root_cause_comparison, confidence, reason. preferred must be current, challenger, or undetermined."
)


def normalize_cwe(value: object) -> str:
    match = CWE_PATTERN.search(str(value or ""))
    return f"CWE-{match.group(1)}" if match else ""


def extract_cwes(value: object) -> list[str]:
    return list(dict.fromkeys(f"CWE-{match}" for match in CWE_PATTERN.findall(str(value or ""))))


def add_candidate(
    candidates: dict[str, dict], value: object, source: str, priority: int
) -> None:
    for cwe in extract_cwes(value):
        item = candidates.setdefault(cwe, {"priority": priority, "sources": []})
        item["priority"] = max(int(item["priority"]), priority)
        if source not in item["sources"]:
            item["sources"].append(source)


def collect_candidates(record: dict) -> list[dict]:
    candidates: dict[str, dict] = {}
    trace = record.get("hybrid_trace") or {}
    diagnosis = record.get("diagnosis") or {}
    plan = record.get("orchestrator_plan") or {}

    add_candidate(candidates, diagnosis.get("cwe_id"), "hybrid_selected", 100)
    add_candidate(candidates, trace.get("agent_cwe"), "agent_final", 95)
    add_candidate(candidates, trace.get("baseline_cwe"), "kg_baseline", 90)

    for report in record.get("agent_reports") or []:
        verdict = str(report.get("verdict") or "")
        prefix = "supported_verifier" if verdict == "supported" else "verifier"
        priority = 85 if verdict == "supported" else 65
        add_candidate(candidates, report.get("recommended_cwe"), f"{prefix}_recommended", priority)
        add_candidate(candidates, report.get("target_cwe"), f"{prefix}_target", priority - 2)

    for hypothesis in plan.get("vulnerability_hypotheses") or []:
        add_candidate(candidates, hypothesis.get("cwe_id"), "orchestrator_hypothesis", 75)
    for value in plan.get("context_possible_cwes") or []:
        add_candidate(candidates, value, "orchestrator_context", 70)
    for warning in record.get("graph_warnings") or []:
        add_candidate(candidates, warning.get("cwe_id"), "graph_warning", 55)

    return [
        {"cwe": cwe, **metadata}
        for cwe, metadata in sorted(
            candidates.items(), key=lambda item: (-int(item[1]["priority"]), item[0])
        )
    ]


def load_cwe_names(path: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            cwe_id = str(row.get("CWE-ID") or "").strip()
            if cwe_id:
                names[f"CWE-{cwe_id}"] = str(row.get("Name") or "").strip()
    return names


def truncate_middle(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    half = max(1, (limit - 80) // 2)
    return text[:half] + "\n/* ... source truncated ... */\n" + text[-half:]


def candidate_context(record: dict, candidate_cwe: str) -> str:
    chunks = []
    plan = record.get("orchestrator_plan") or {}
    for hypothesis in plan.get("vulnerability_hypotheses") or []:
        if candidate_cwe in extract_cwes(hypothesis.get("cwe_id")):
            chunks.append(f"Orchestrator hypothesis: {hypothesis.get('reason', '')}")

    for report in record.get("agent_reports") or []:
        report_cwes = set(extract_cwes(report.get("target_cwe"))) | set(
            extract_cwes(report.get("recommended_cwe"))
        )
        if candidate_cwe not in report_cwes:
            continue
        chunks.append(
            f"Verifier verdict={report.get('verdict', '')} confidence={report.get('confidence', '')}: "
            f"{report.get('summary', '')}"
        )
        for evidence in (report.get("code_evidence") or [])[:3]:
            chunks.append(
                f"Verifier evidence [{evidence.get('evidence_type', '')}]: "
                f"{evidence.get('line_or_snippet', '')} | {evidence.get('analysis', '')}"
            )

    for warning in record.get("graph_warnings") or []:
        if candidate_cwe not in extract_cwes(warning.get("cwe_id")):
            continue
        chunks.append(
            f"KG clue for entity {warning.get('entity', '')}: {warning.get('warning', '')}"
        )
        if warning.get("verification_contract"):
            chunks.append(f"Verification checklist: {warning['verification_contract']}")

    return truncate_middle("\n".join(chunks), 4500) or "No candidate-specific prior context."


def build_conversation(
    record: dict,
    code: str,
    candidate: dict,
    cwe_names: dict[str, str],
    code_char_limit: int,
) -> list[dict]:
    cwe = candidate["cwe"]
    name = cwe_names.get(cwe, "Unknown CWE name")
    provenance = ", ".join(candidate["sources"])
    user_prompt = (
        f"Sample ID: {record.get('sample_id', '')}\n"
        f"Candidate: {cwe} - {name}\n"
        f"Candidate provenance: {provenance}\n\n"
        f"Candidate-specific prior context:\n{candidate_context(record, cwe)}\n\n"
        f"Source code (infer its language):\n```text\n{truncate_middle(code, code_char_limit)}\n```\n\n"
        "Return the required JSON object only. /no_think"
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def summarize_evaluation(evaluation: dict | None) -> str:
    if not evaluation:
        return "No independent candidate evaluation is available."
    return (
        f"supported={evaluation.get('mechanism_supported', False)}; "
        f"score={evaluation.get('score', 0.0)}; "
        f"dangerous_operation={evaluation.get('dangerous_operation', '')}; "
        f"reason={evaluation.get('reason', '')}"
    )


def build_pairwise_conversation(
    record: dict,
    code: str,
    current_cwe: str,
    challenger_cwe: str,
    evaluations: list[dict],
    cwe_names: dict[str, str],
    code_char_limit: int,
) -> list[dict]:
    by_cwe = {item.get("candidate_cwe"): item for item in evaluations}
    user_prompt = (
        f"Sample ID: {record.get('sample_id', '')}\n"
        f"Current CWE: {current_cwe} - {cwe_names.get(current_cwe, 'Unknown CWE name')}\n"
        f"Challenger CWE: {challenger_cwe} - {cwe_names.get(challenger_cwe, 'Unknown CWE name')}\n\n"
        f"Current candidate context:\n{candidate_context(record, current_cwe)}\n"
        f"Independent current evaluation:\n{summarize_evaluation(by_cwe.get(current_cwe))}\n\n"
        f"Challenger context:\n{candidate_context(record, challenger_cwe)}\n"
        f"Independent challenger evaluation:\n{summarize_evaluation(by_cwe.get(challenger_cwe))}\n\n"
        f"Source code (infer its language):\n```text\n{truncate_middle(code, code_char_limit)}\n```\n\n"
        "Compare only these two labels and return the required JSON object. /no_think"
    )
    return [
        {"role": "system", "content": PAIRWISE_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def extract_json_object(raw_text: str) -> dict:
    text = raw_text or ""
    if "</think>" in text:
        text = text.split("</think>", 1)[1]
    text = text.replace("<think>", "").strip()
    fenced = re.findall(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced[-1].strip()
    decoder = json.JSONDecoder()
    for match in reversed(list(re.finditer(r"\{", text))):
        try:
            value, _ = decoder.raw_decode(text[match.start() :])
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    raise ValueError("No valid JSON object found")


def clamp(value: object, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def normalize_verification(raw_text: str, expected_cwe: str) -> dict:
    try:
        data = extract_json_object(raw_text)
        returned_cwe = normalize_cwe(data.get("candidate_cwe"))
        if returned_cwe and returned_cwe != expected_cwe:
            raise ValueError(f"candidate mismatch: expected {expected_cwe}, got {returned_cwe}")
        supported_value = data.get("mechanism_supported", False)
        if isinstance(supported_value, str):
            supported = supported_value.strip().lower() in {"true", "yes", "supported", "1"}
        else:
            supported = bool(supported_value)
        operation = str(data.get("dangerous_operation") or "").strip()
        root_cause_fit = clamp(data.get("root_cause_fit"))
        evidence_strength = clamp(data.get("evidence_strength"))
        specificity = clamp(data.get("specificity"))
        confidence = clamp(data.get("confidence"), 0.5)
        score = (
            0.45 * root_cause_fit
            + 0.25 * evidence_strength
            + 0.15 * specificity
            + 0.15 * confidence
        )
        if not supported:
            score *= 0.25
        if not operation:
            score = min(score, 0.55)
        return {
            "candidate_cwe": expected_cwe,
            "mechanism_supported": supported,
            "dangerous_operation": operation,
            "root_cause_fit": root_cause_fit,
            "evidence_strength": evidence_strength,
            "specificity": specificity,
            "confidence": confidence,
            "score": round(score, 4),
            "reason": str(data.get("reason") or "").strip(),
            "parse_error": "",
            "raw_output": raw_text,
        }
    except Exception as exc:
        return {
            "candidate_cwe": expected_cwe,
            "mechanism_supported": False,
            "dangerous_operation": "",
            "root_cause_fit": 0.0,
            "evidence_strength": 0.0,
            "specificity": 0.0,
            "confidence": 0.0,
            "score": 0.0,
            "reason": "",
            "parse_error": str(exc),
            "raw_output": raw_text,
        }


def normalize_pairwise(
    raw_text: str,
    expected_current: str,
    expected_challenger: str,
) -> dict:
    try:
        data = extract_json_object(raw_text)
        returned_current = normalize_cwe(data.get("current_cwe"))
        returned_challenger = normalize_cwe(data.get("challenger_cwe"))
        if returned_current != expected_current:
            raise ValueError(
                f"current mismatch: expected {expected_current}, got {returned_current or '<missing>'}"
            )
        if returned_challenger != expected_challenger:
            raise ValueError(
                f"challenger mismatch: expected {expected_challenger}, got {returned_challenger or '<missing>'}"
            )

        raw_preferred = str(data.get("preferred") or "undetermined").strip()
        preferred_cwe = normalize_cwe(raw_preferred)
        if preferred_cwe == expected_current:
            preferred = "current"
        elif preferred_cwe == expected_challenger:
            preferred = "challenger"
        else:
            preferred = raw_preferred.lower()
        if preferred not in {"current", "challenger", "undetermined"}:
            raise ValueError(f"invalid preferred value: {preferred}")

        def as_bool(value: object) -> bool:
            if isinstance(value, str):
                return value.strip().lower() in {"true", "yes", "supported", "1"}
            return bool(value)

        return {
            "current_cwe": expected_current,
            "challenger_cwe": expected_challenger,
            "code_language": str(data.get("code_language") or "").strip(),
            "preferred": preferred,
            "current_refuted": as_bool(data.get("current_refuted", False)),
            "challenger_supported": as_bool(data.get("challenger_supported", False)),
            "current_refutation": str(data.get("current_refutation") or "").strip(),
            "challenger_evidence": str(data.get("challenger_evidence") or "").strip(),
            "root_cause_comparison": str(data.get("root_cause_comparison") or "").strip(),
            "confidence": clamp(data.get("confidence"), 0.0),
            "reason": str(data.get("reason") or "").strip(),
            "parse_error": "",
            "raw_output": raw_text,
        }
    except Exception as exc:
        return {
            "current_cwe": expected_current,
            "challenger_cwe": expected_challenger,
            "code_language": "",
            "preferred": "undetermined",
            "current_refuted": False,
            "challenger_supported": False,
            "current_refutation": "",
            "challenger_evidence": "",
            "root_cause_comparison": "",
            "confidence": 0.0,
            "reason": "",
            "parse_error": str(exc),
            "raw_output": raw_text,
        }


def llm_chat(llm, conversations: list[list[dict]], sampling_params):
    """Render prompts explicitly so old vLLM cannot drop enable_thinking=False."""
    tokenizer = llm.get_tokenizer()
    prompts = []
    for conversation in conversations:
        try:
            prompt = tokenizer.apply_chat_template(
                conversation,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            prompt = tokenizer.apply_chat_template(
                conversation,
                tokenize=False,
                add_generation_prompt=True,
            )
        prompts.append(prompt)
    return llm.generate(prompts, sampling_params=sampling_params, use_tqdm=True)


def patch_transformers_tokenizers() -> None:
    """Apply the same slow-tokenizer compatibility patch as the historical runners."""
    import transformers
    import transformers.tokenization_utils
    import transformers.tokenization_utils_base

    @property
    def all_special_tokens_extended(self):
        return self.all_special_tokens

    classes = [
        getattr(transformers, "PreTrainedTokenizer", None),
        getattr(transformers.tokenization_utils, "PreTrainedTokenizer", None),
        getattr(transformers, "PreTrainedTokenizerBase", None),
        getattr(transformers.tokenization_utils_base, "PreTrainedTokenizerBase", None),
    ]
    for tokenizer_class in classes:
        if tokenizer_class is not None and not hasattr(tokenizer_class, "all_special_tokens_extended"):
            tokenizer_class.all_special_tokens_extended = all_special_tokens_extended
    print("=== [MONKEYPATCH] Successfully patched transformers tokenizers ===")


def load_samples(config: dict) -> dict[str, object]:
    sys.path.insert(0, str(AGENT_DIR))
    try:
        from data_loader import DataLoader

        loader = DataLoader(config["paths"]["cve_dir"], config["paths"]["synthetic_dir"])
        return {sample.sample_id: sample for sample in loader.load_all()}
    finally:
        sys.path.pop(0)


def choose_cwe(
    current_cwe: str,
    evaluations: list[dict],
    min_score: float,
    min_margin: float,
) -> tuple[str, str]:
    ranked = sorted(evaluations, key=lambda item: (-float(item["score"]), item["candidate_cwe"]))
    if not ranked:
        return current_cwe, "no_candidate_evaluations"
    top = ranked[0]
    if top["candidate_cwe"] == current_cwe:
        return current_cwe, "current_candidate_remains_top"
    if not top["mechanism_supported"] or not top["dangerous_operation"]:
        return current_cwe, "top_candidate_lacks_concrete_supported_evidence"
    if float(top["score"]) < min_score:
        return current_cwe, f"top_score_below_threshold:{top['score']:.4f}<{min_score:.4f}"

    current = next((item for item in ranked if item["candidate_cwe"] == current_cwe), None)
    current_score = float(current["score"]) if current else 0.0
    margin = float(top["score"]) - current_score
    if margin < min_margin:
        return current_cwe, f"score_margin_too_small:{margin:.4f}<{min_margin:.4f}"
    return top["candidate_cwe"], f"evidence_override:score={top['score']:.4f},margin={margin:.4f}"


def load_checkpoint(path: Path, expected_version: int) -> dict:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    version = (payload.get("_meta") or {}).get("version")
    if version == expected_version:
        return payload.get("samples") or {}

    invalid_path = path.with_name(
        f"{path.stem}.invalid_v{version or 1}{path.suffix}"
    )
    if invalid_path.exists():
        invalid_path.unlink()
    path.replace(invalid_path)
    print(f"Archived incompatible checkpoint: {invalid_path.name}")
    return {}


def write_checkpoint(path: Path, values: dict, version: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    payload = {
        "_meta": {"version": version, "thinking_disabled": True},
        "samples": values,
    }
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_path.replace(path)


def evidence_quotes_source(evidence: str, source_code: str) -> bool:
    def compact(value: str) -> str:
        return re.sub(r"\s+", " ", value).strip()

    normalized_code = compact(source_code)
    normalized_evidence = compact(evidence)
    if len(normalized_evidence) >= 4 and normalized_evidence in normalized_code:
        return True

    # Pairwise outputs commonly append an explanation after an exact snippet.
    snippet_prefix = evidence.split(" | ", 1)[0].strip().strip("`\"'")
    normalized_prefix = compact(snippet_prefix)
    if len(normalized_prefix) >= 4 and normalized_prefix in normalized_code:
        return True

    quoted = re.findall(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", evidence)
    for groups in quoted:
        snippet = compact(next((item for item in groups if item), ""))
        if len(snippet) >= 4 and snippet in normalized_code:
            return True
    return False


def accept_pairwise_override(
    current_cwe: str,
    challenger_cwe: str,
    decision: dict | None,
    min_confidence: float,
    source_code: str,
) -> tuple[str, str]:
    if not decision:
        return current_cwe, "pairwise_decision_missing"
    if decision.get("parse_error"):
        return current_cwe, f"pairwise_parse_error:{decision['parse_error']}"
    if decision.get("preferred") != "challenger":
        return current_cwe, f"pairwise_kept_current:{decision.get('preferred', 'undetermined')}"
    if not decision.get("current_refuted") or not decision.get("current_refutation"):
        return current_cwe, "pairwise_current_not_concretely_refuted"
    if not decision.get("challenger_supported") or not decision.get("challenger_evidence"):
        return current_cwe, "pairwise_challenger_lacks_concrete_evidence"
    if not evidence_quotes_source(str(decision["challenger_evidence"]), source_code):
        return current_cwe, "pairwise_challenger_evidence_not_found_in_source"
    if not decision.get("root_cause_comparison"):
        return current_cwe, "pairwise_root_cause_comparison_missing"
    confidence = float(decision.get("confidence") or 0.0)
    if confidence < min_confidence:
        return current_cwe, (
            f"pairwise_confidence_below_threshold:{confidence:.4f}<{min_confidence:.4f}"
        )
    return challenger_cwe, f"pairwise_override:confidence={confidence:.4f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Candidate-wise CWE evidence refinement with frozen Hybrid binary verdicts."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--code-char-limit", type=int, default=8000)
    parser.add_argument("--min-score", type=float, default=0.78)
    parser.add_argument("--min-margin", type=float, default=0.12)
    parser.add_argument("--pairwise-min-confidence", type=float, default=0.80)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    records = json.loads(args.input.read_text(encoding="utf-8"))
    cwe_names = load_cwe_names(ROOT / "1000.csv")

    candidate_sets: dict[str, list[dict]] = {}
    for record in records:
        if bool((record.get("diagnosis") or {}).get("is_vulnerable")):
            candidate_sets[record["sample_id"]] = collect_candidates(record)

    total_candidates = sum(len(items) for items in candidate_sets.values())
    print(
        f"CWE refinement scope: vulnerable_predictions={len(candidate_sets)} "
        f"candidate_evaluations={total_candidates}"
    )
    if args.dry_run:
        return

    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    samples = load_samples(config)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = args.output_dir / "cwe_refinement_checkpoint.json"
    checkpoint = load_checkpoint(checkpoint_path, CHECKPOINT_VERSION)

    pending = []
    record_by_id = {record["sample_id"]: record for record in records}
    for sample_id, candidates in candidate_sets.items():
        if sample_id not in samples:
            raise KeyError(f"Source code not found for sample: {sample_id}")
        completed = checkpoint.get(sample_id, {})
        for candidate in candidates:
            if candidate["cwe"] not in completed:
                pending.append((sample_id, candidate))

    llm = None
    sampling_params_class = None

    def ensure_llm():
        nonlocal llm, sampling_params_class
        if llm is not None:
            return llm, sampling_params_class
        patch_transformers_tokenizers()
        from vllm import LLM, SamplingParams

        llm_conf = config["llm"]["extraction"]
        os.environ["VLLM_USE_V1"] = "0"
        llm = LLM(
            model=llm_conf["model_path"],
            gpu_memory_utilization=float(llm_conf.get("gpu_memory_utilization", 0.9)),
            tensor_parallel_size=int(llm_conf.get("tensor_parallel_size", 1)),
            max_model_len=int(llm_conf.get("max_model_len", 16384)),
            trust_remote_code=True,
        )
        sampling_params_class = SamplingParams
        return llm, sampling_params_class

    if pending:
        llm, sampling_params_class = ensure_llm()
        sampling_params = sampling_params_class(max_tokens=768, temperature=0.0)

        for offset in range(0, len(pending), max(1, args.batch_size)):
            batch = pending[offset : offset + max(1, args.batch_size)]
            conversations = [
                build_conversation(
                    record_by_id[sample_id],
                    samples[sample_id].code,
                    candidate,
                    cwe_names,
                    args.code_char_limit,
                )
                for sample_id, candidate in batch
            ]
            outputs = llm_chat(llm, conversations, sampling_params)
            for (sample_id, candidate), output in zip(batch, outputs):
                raw_text = output.outputs[0].text
                evaluation = normalize_verification(raw_text, candidate["cwe"])
                evaluation["sources"] = candidate["sources"]
                checkpoint.setdefault(sample_id, {})[candidate["cwe"]] = evaluation
            write_checkpoint(checkpoint_path, checkpoint, CHECKPOINT_VERSION)
            print(f"Checkpointed {min(offset + len(batch), len(pending))}/{len(pending)} pending evaluations")

    shortlist: dict[str, dict] = {}
    for record in records:
        if not bool((record.get("diagnosis") or {}).get("is_vulnerable")):
            continue
        sample_id = record["sample_id"]
        current_cwe = normalize_cwe((record.get("diagnosis") or {}).get("cwe_id"))
        evaluations = list((checkpoint.get(sample_id) or {}).values())
        challenger_cwe, screening_reason = choose_cwe(
            current_cwe,
            evaluations,
            args.min_score,
            args.min_margin,
        )
        shortlist[sample_id] = {
            "current_cwe": current_cwe,
            "challenger_cwe": challenger_cwe,
            "screening_reason": screening_reason,
            "evaluations": evaluations,
        }

    pairwise_checkpoint_path = args.output_dir / "cwe_pairwise_checkpoint.json"
    pairwise_checkpoint = load_checkpoint(
        pairwise_checkpoint_path, PAIRWISE_CHECKPOINT_VERSION
    )
    pairwise_pending = []
    for sample_id, item in shortlist.items():
        current_cwe = item["current_cwe"]
        challenger_cwe = item["challenger_cwe"]
        if not current_cwe or not challenger_cwe or challenger_cwe == current_cwe:
            continue
        pair_key = f"{current_cwe}|{challenger_cwe}"
        if pair_key not in (pairwise_checkpoint.get(sample_id) or {}):
            pairwise_pending.append((sample_id, pair_key, item))

    print(f"Pairwise adjudication scope: pending={len(pairwise_pending)}")
    if pairwise_pending:
        llm, sampling_params_class = ensure_llm()
        pairwise_sampling_params = sampling_params_class(max_tokens=1024, temperature=0.0)
        for offset in range(0, len(pairwise_pending), max(1, args.batch_size)):
            batch = pairwise_pending[offset : offset + max(1, args.batch_size)]
            conversations = [
                build_pairwise_conversation(
                    record_by_id[sample_id],
                    samples[sample_id].code,
                    item["current_cwe"],
                    item["challenger_cwe"],
                    item["evaluations"],
                    cwe_names,
                    args.code_char_limit,
                )
                for sample_id, _, item in batch
            ]
            outputs = llm_chat(llm, conversations, pairwise_sampling_params)
            for (sample_id, pair_key, item), output in zip(batch, outputs):
                decision = normalize_pairwise(
                    output.outputs[0].text,
                    item["current_cwe"],
                    item["challenger_cwe"],
                )
                pairwise_checkpoint.setdefault(sample_id, {})[pair_key] = decision
            write_checkpoint(
                pairwise_checkpoint_path,
                pairwise_checkpoint,
                PAIRWISE_CHECKPOINT_VERSION,
            )
            print(
                f"Checkpointed {min(offset + len(batch), len(pairwise_pending))}/"
                f"{len(pairwise_pending)} pairwise decisions"
            )

    refined = copy.deepcopy(records)
    changed = 0
    for before, after in zip(records, refined):
        before_binary = bool((before.get("diagnosis") or {}).get("is_vulnerable"))
        after_binary = bool((after.get("diagnosis") or {}).get("is_vulnerable"))
        if before_binary != after_binary:
            raise AssertionError(f"Binary verdict changed before refinement: {before.get('sample_id')}")
        if not before_binary:
            continue

        sample_id = before["sample_id"]
        current_cwe = normalize_cwe((before.get("diagnosis") or {}).get("cwe_id"))
        item = shortlist[sample_id]
        evaluations = item["evaluations"]
        challenger_cwe = item["challenger_cwe"]
        screening_reason = item["screening_reason"]
        pairwise_decision = None
        if challenger_cwe and challenger_cwe != current_cwe:
            if not current_cwe:
                selected_cwe = challenger_cwe
                reason = "independent_override_without_current_cwe"
            else:
                pair_key = f"{current_cwe}|{challenger_cwe}"
                pairwise_decision = (pairwise_checkpoint.get(sample_id) or {}).get(pair_key)
                selected_cwe, reason = accept_pairwise_override(
                    current_cwe,
                    challenger_cwe,
                    pairwise_decision,
                    args.pairwise_min_confidence,
                    samples[sample_id].code,
                )
        else:
            selected_cwe = current_cwe
            reason = screening_reason
        if selected_cwe and selected_cwe != current_cwe:
            after["diagnosis"]["cwe_id"] = selected_cwe
            after["diagnosis"]["vulnerability_type"] = cwe_names.get(selected_cwe, "")
            changed += 1
        after["cwe_refinement"] = {
            "binary_verdict_frozen": True,
            "original_cwe": current_cwe,
            "selected_cwe": selected_cwe or current_cwe,
            "changed": bool(selected_cwe and selected_cwe != current_cwe),
            "selection_reason": reason,
            "screened_challenger": challenger_cwe,
            "screening_reason": screening_reason,
            "min_score": args.min_score,
            "min_margin": args.min_margin,
            "pairwise_min_confidence": args.pairwise_min_confidence,
            "pairwise_decision": pairwise_decision,
            "candidate_evaluations": sorted(
                evaluations,
                key=lambda item: (-float(item["score"]), item["candidate_cwe"]),
            ),
        }

    for before, after in zip(records, refined):
        if bool((before.get("diagnosis") or {}).get("is_vulnerable")) != bool(
            (after.get("diagnosis") or {}).get("is_vulnerable")
        ):
            raise AssertionError(f"Binary invariant violated: {before.get('sample_id')}")

    result_path = args.output_dir / "detection_results_hybrid_cwe_refined.json"
    result_path.write_text(json.dumps(refined, ensure_ascii=False, indent=2), encoding="utf-8")

    cwe_dict = evaluate.build_cwe_hierarchy(ROOT / "1000.csv")
    report = evaluate.evaluate_all(refined, cwe_dict)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_report = args.output_dir / f"evaluation_report_hybrid_cwe_refined_{timestamp}.json"
    md_report = args.output_dir / f"evaluation_report_hybrid_cwe_refined_{timestamp}.md"
    json_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_report.write_text(evaluate.generate_markdown_report(report), encoding="utf-8")

    overall = report["overall"]
    print(
        f"Refinement complete: changed_cwe={changed} "
        f"TP={overall['tp']} FP={overall['fp']} FN={overall['fn']} TN={overall['tn']} "
        f"CWE={overall['cwe_hit_rate']:.4f} "
        f"({overall['cwe_hit_count']}/{overall['cwe_total']}) "
        f"H={overall['cwe_h_hit_rate']:.4f}"
    )
    print(f"result: {result_path}")
    print(f"report: {md_report}")


if __name__ == "__main__":
    main()
