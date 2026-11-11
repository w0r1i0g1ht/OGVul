"""Run the unified global-local multi-agent experiment in resumable stages."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent


def run(command: list[str]) -> None:
    print(f"[unified-agent] run={' '.join(command)}")
    subprocess.run(command, cwd=ROOT, check=True)


def load_config(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate_complete(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Detection result does not exist: {path}")
    rows = json.loads(path.read_text(encoding="utf-8"))
    incomplete = [
        str(row.get("sample_id") or "<missing>")
        for row in rows
        if row.get("status") != "success" or not isinstance(row.get("diagnosis"), dict)
    ]
    if len(rows) != 280 or incomplete:
        preview = ", ".join(incomplete[:12]) or "none"
        raise RuntimeError(
            f"Detection result is incomplete: rows={len(rows)}, "
            f"incomplete={len(incomplete)}, samples={preview}. "
            "Rerun the detect stage before CWE refinement."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified code-only multi-agent ablation runner")
    parser.add_argument("--config", type=Path, default=ROOT / "config.yaml")
    parser.add_argument("--stage", choices=("all", "detect", "refine"), default="all")
    args = parser.parse_args()

    config = load_config(args.config)
    output_dir = Path(config["paths"]["output_dir"])
    result_name = config.get("runtime", {}).get(
        "result_file", "detection_results_unified_agent_without_kg.json"
    )
    detection_result = output_dir / result_name
    refined_dir = output_dir / "cwe_refined"
    output_dir.mkdir(parents=True, exist_ok=True)

    python = sys.executable
    if args.stage in {"all", "detect"}:
        run([python, "main_agent_offline.py", "--config", str(args.config)])

    if args.stage in {"all", "refine"}:
        validate_complete(detection_result)
        run(
            [
                python,
                "cwe_refine_offline.py",
                "--input",
                str(detection_result),
                "--config",
                str(args.config),
                "--output-dir",
                str(refined_dir),
            ]
        )


if __name__ == "__main__":
    main()
