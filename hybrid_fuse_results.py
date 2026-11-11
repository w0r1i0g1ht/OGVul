"""Fuse strong binary detection with agent CWE localization.

The hybrid strategy is intentionally simple and reproducible:

1. Use the baseline KG-RAG result for binary vulnerability detection.
2. For samples predicted vulnerable by the baseline, use the agent CWE if present.
3. If the agent has no CWE, fall back to the baseline CWE.
4. For samples predicted safe by the baseline, clear CWE fields.
"""

from __future__ import annotations

import argparse
import copy
import json
from datetime import datetime
from pathlib import Path

import evaluate


ROOT = Path(__file__).resolve().parent
DEFAULT_BASE = ROOT / "outputs" / "kg" / "detection_results_kg_rag.json"
DEFAULT_AGENT = ROOT / "outputs" / "agent" / "detection_results_agent_kg_rag.json"
DEFAULT_OUTPUT_DIR = ROOT / "outputs" / "hybrid"


def load_json(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError(f"expected list result file: {path}")
    return data


def diagnosis(record: dict) -> dict:
    record.setdefault("diagnosis", {})
    return record["diagnosis"]


def is_vulnerable(record: dict) -> bool:
    return bool((record.get("diagnosis") or {}).get("is_vulnerable"))


def merge_warnings(*groups: list[dict]) -> list[dict]:
    seen = set()
    merged = []
    for warnings in groups:
        for warning in warnings or []:
            key = (
                warning.get("entity", ""),
                warning.get("warning", ""),
                warning.get("cwe_id", ""),
                warning.get("verification_contract", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(warning)
    return merged


def fuse_records(
    base_rows: list[dict],
    agent_rows: list[dict],
    mode: str,
) -> list[dict]:
    agent_by_id = {row["sample_id"]: row for row in agent_rows}
    fused = []
    for base in base_rows:
        row = copy.deepcopy(base)
        sample_id = row["sample_id"]
        agent = agent_by_id.get(sample_id, {})
        base_diag = base.get("diagnosis") or {}
        agent_diag = agent.get("diagnosis") or {}
        out_diag = diagnosis(row)

        binary_pred = bool(base_diag.get("is_vulnerable"))
        out_diag["is_vulnerable"] = binary_pred

        if binary_pred:
            agent_cwe = agent_diag.get("cwe_id") or ""
            base_cwe = base_diag.get("cwe_id") or ""
            selected_cwe = agent_cwe or base_cwe
            out_diag["cwe_id"] = selected_cwe
            if agent_cwe:
                out_diag["vulnerability_type"] = (
                    agent_diag.get("vulnerability_type")
                    or base_diag.get("vulnerability_type", "")
                )
                out_diag["affected_lines"] = (
                    agent_diag.get("affected_lines")
                    or base_diag.get("affected_lines", [])
                )
                out_diag["graph_warning_critique"] = agent_diag.get(
                    "graph_warning_critique", ""
                )
            source = "agent" if agent_cwe else "baseline fallback"
            out_diag["explanation"] = (
                "Hybrid fusion: binary verdict from baseline KG-RAG; "
                f"CWE from {source}."
            )
        else:
            out_diag["cwe_id"] = ""
            out_diag["vulnerability_type"] = ""
            out_diag["affected_lines"] = []
            out_diag["explanation"] = (
                "Hybrid fusion: baseline KG-RAG classified the sample as non-vulnerable."
            )

        row["pipeline_mode"] = mode
        row["hybrid_trace"] = {
            "binary_source": "kg",
            "cwe_source": "agent",
            "cwe_policy": "agent_cwe_else_baseline_cwe",
            "baseline_cwe": base_diag.get("cwe_id", ""),
            "agent_cwe": agent_diag.get("cwe_id", ""),
            "selected_cwe": out_diag.get("cwe_id", ""),
        }
        row["graph_warnings"] = merge_warnings(
            base.get("graph_warnings", []),
            agent.get("graph_warnings", []),
        )
        row["agent_reports"] = agent.get("agent_reports", [])
        row["orchestrator_plan"] = agent.get("orchestrator_plan")
        fused.append(row)
    return fused


def write_report(
    records: list[dict], output_dir: Path, mode: str
) -> tuple[Path, Path]:
    cwe_dict = evaluate.build_cwe_hierarchy(ROOT / "1000.csv")
    report = evaluate.evaluate_all(records, cwe_dict)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"evaluation_report_{mode}_{timestamp}.json"
    md_path = output_dir / f"evaluation_report_{mode}_{timestamp}.md"
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    with md_path.open("w", encoding="utf-8") as fh:
        fh.write(evaluate.generate_markdown_report(report))
    return json_path, md_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hybrid fuse baseline binary and agent CWE results."
    )
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--agent", type=Path, default=DEFAULT_AGENT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--mode", default="hybrid_kg_agent")
    args = parser.parse_args()

    base_rows = load_json(args.base)
    agent_rows = load_json(args.agent)
    if len(base_rows) != len(agent_rows):
        print(f"warning: base rows={len(base_rows)} agent rows={len(agent_rows)}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    fused = fuse_records(base_rows, agent_rows, args.mode)
    result_path = args.output_dir / f"detection_results_{args.mode}.json"
    with result_path.open("w", encoding="utf-8") as fh:
        json.dump(fused, fh, ensure_ascii=False, indent=2)

    json_report, md_report = write_report(fused, args.output_dir, args.mode)
    overall = evaluate.evaluate_group(
        fused,
        evaluate.build_cwe_hierarchy(ROOT / "1000.csv"),
        "Overall",
    )
    print(f"result: {result_path}")
    print(f"json_report: {json_report}")
    print(f"md_report: {md_report}")
    print(
        f"summary: TP={overall['tp']} FP={overall['fp']} "
        f"FN={overall['fn']} TN={overall['tn']} "
        f"P={overall['precision']:.4f} R={overall['recall']:.4f} "
        f"F1={overall['f1']:.4f} Acc={overall['accuracy']:.4f} "
        f"CWE={overall['cwe_hit_rate']:.4f} "
        f"({overall['cwe_hit_count']}/{overall['cwe_total']}) "
        f"H={overall['cwe_h_hit_rate']:.4f}"
    )


if __name__ == "__main__":
    main()
