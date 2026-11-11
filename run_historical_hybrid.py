"""Run the source-level historical Hybrid experiment in three stages."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent
KG_DIR = ROOT / "kg"
AGENT_DIR = ROOT / "agent"
OUTPUT_ROOT = ROOT / "outputs"


def run(command: list[str], cwd: Path) -> None:
    print(f"[historical-hybrid] cwd={cwd}")
    print(f"[historical-hybrid] run={' '.join(command)}")
    subprocess.run(command, cwd=cwd, check=True)


def _sample_digest(code: str, info_path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(code.encode("utf-8"))
    digest.update(b"\0")
    if info_path.is_file():
        digest.update(info_path.read_bytes())
    return digest.hexdigest()


def _extract_markdown_code(path: Path) -> str:
    if not path.is_file():
        return ""
    content = path.read_text(encoding="utf-8")
    matches = re.findall(r"```[a-zA-Z+]*\s*\n(.*?)```", content, re.DOTALL)
    return "\n\n".join(match.strip() for match in matches)


def discover_dataset_samples(dataset_dir: Path) -> dict[str, str]:
    """Return the loadable sample IDs and content hashes used by DataLoader."""
    if not dataset_dir.is_dir():
        raise FileNotFoundError(f"Dataset directory does not exist: {dataset_dir}")

    samples: dict[str, str] = {}
    for path in dataset_dir.iterdir():
        if not path.is_dir():
            continue
        if path.name.startswith("Sample_"):
            for filename, suffix in (
                ("mutated_code.cpp", "vuln"),
                ("safe_code.cpp", "safe"),
            ):
                code_path = path / filename
                if not code_path.is_file():
                    continue
                code = code_path.read_text(encoding="utf-8")
                if not code.strip():
                    continue
                sample_id = f"{path.name}_{suffix}"
                samples[sample_id] = _sample_digest(code, path / "vuln_info.json")
        elif path.name.startswith("CVE-"):
            code = _extract_markdown_code(path / "vuln_code.md")
            if not code:
                continue
            samples[path.name] = _sample_digest(code, path / "vuln_info.json")
    return samples


def count_dataset_samples(dataset_dir: Path) -> int:
    samples = discover_dataset_samples(dataset_dir)
    if not samples:
        raise RuntimeError(f"No supported samples found in dataset directory: {dataset_dir}")
    return len(samples)


def resolve_output_root(experiment_name: str) -> Path:
    if not experiment_name:
        return OUTPUT_ROOT.resolve()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", experiment_name):
        raise ValueError(
            "--experiment-name must be a safe name containing only letters, "
            "digits, dots, underscores, and hyphens"
        )
    return (OUTPUT_ROOT / experiment_name).resolve()


def ensure_dataset_manifest(
    output_root: Path,
    dataset_dir: Path,
    samples: dict[str, str],
    config_hashes: dict[str, str] | None = None,
    graph_version: str = "unspecified",
    upgrade_legacy: bool = False,
) -> Path:
    manifest_path = output_root / "dataset_manifest.json"
    payload = {
        "version": 1,
        "dataset_dir": dataset_dir.as_posix(),
        "sample_count": len(samples),
        "samples": dict(sorted(samples.items())),
        "config_hashes": dict(sorted((config_hashes or {}).items())),
        "graph_version": graph_version,
    }
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing.get("samples") != payload["samples"]:
            raise RuntimeError(
                f"The dataset content changed for this experiment: {manifest_path}. "
                "Use a new --experiment-name to keep results isolated."
            )
        existing_hashes = existing.get("config_hashes", {})
        existing_graph_version = existing.get("graph_version", "unspecified")
        config_changed = existing_hashes != payload["config_hashes"]
        graph_changed = existing_graph_version != graph_version
        legacy_upgrade_allowed = not existing_hashes or (
            not config_changed and existing_graph_version == "unspecified"
        )
        if (config_changed or graph_changed) and upgrade_legacy and legacy_upgrade_allowed:
            saved_config_paths = {
                "kg": output_root / "configs" / "kg.yaml",
                "agent": output_root / "configs" / "agent.yaml",
            }
            missing_configs = [
                str(path) for path in saved_config_paths.values() if not path.is_file()
            ]
            if missing_configs:
                raise RuntimeError(
                    "Cannot upgrade legacy manifest because saved configs are missing: "
                    + ", ".join(missing_configs)
                )
            saved_hashes = {
                name: config_digest(yaml.safe_load(path.read_text(encoding="utf-8")))
                for name, path in saved_config_paths.items()
            }
            if saved_hashes != payload["config_hashes"]:
                raise RuntimeError(
                    "Cannot upgrade legacy manifest because the saved effective "
                    "configuration differs from the current configuration."
                )
            if existing_graph_version not in {"unspecified", graph_version}:
                raise RuntimeError(
                    "Cannot upgrade legacy manifest because its graph version conflicts "
                    "with --graph-version."
                )
            manifest_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return manifest_path
        if config_changed or graph_changed:
            raise RuntimeError(
                f"The effective configuration changed for this experiment: {manifest_path}. "
                "For a legacy manifest, verify the original stage configs and pass "
                "--upgrade-legacy-manifest once; otherwise use a new --experiment-name."
            )
        return manifest_path

    if output_root.exists() and any(output_root.iterdir()):
        raise RuntimeError(
            f"Experiment directory is not empty but has no dataset manifest: {output_root}. "
            "Use a new --experiment-name to avoid adopting unknown results."
        )
    output_root.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return manifest_path


def build_experiment_config(
    base_config: dict,
    dataset_dir: Path,
    output_dir: Path,
) -> dict:
    configured = copy.deepcopy(base_config)
    paths = configured.setdefault("paths", {})
    paths["cve_dir"] = dataset_dir.as_posix()
    paths["synthetic_dir"] = dataset_dir.as_posix()
    paths["output_dir"] = output_dir.as_posix()
    return configured


def config_digest(config: dict) -> str:
    serialized = json.dumps(
        config,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def select_effective_configs(
    stage: str,
    base_kg_config: dict,
    base_agent_config: dict,
    dataset_dir: Path,
    output_root: Path,
) -> tuple[dict, dict, bool]:
    config_root = output_root / "configs"
    saved_kg_path = config_root / "kg.yaml"
    saved_agent_path = config_root / "agent.yaml"
    if stage in {"fuse", "refine"}:
        missing = [
            str(path)
            for path in (saved_kg_path, saved_agent_path)
            if not path.is_file()
        ]
        if missing:
            raise FileNotFoundError(
                "Cannot resume fusion/refinement because saved stage configs are missing: "
                + ", ".join(missing)
            )
        return (
            yaml.safe_load(saved_kg_path.read_text(encoding="utf-8")),
            yaml.safe_load(saved_agent_path.read_text(encoding="utf-8")),
            False,
        )

    return (
        build_experiment_config(
            base_kg_config,
            dataset_dir,
            output_root / "kg",
        ),
        build_experiment_config(
            base_agent_config,
            dataset_dir,
            output_root / "agent",
        ),
        True,
    )


def write_experiment_config(
    source_path: Path,
    destination_path: Path,
    dataset_dir: Path,
    output_dir: Path,
) -> None:
    base_config = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    configured = build_experiment_config(base_config, dataset_dir, output_dir)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text(
        yaml.safe_dump(configured, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def validate_result_file(
    path: Path,
    label: str,
    expected_samples: int,
) -> set[str]:
    with path.open("r", encoding="utf-8") as fh:
        rows = json.load(fh)
    if not isinstance(rows, list):
        raise RuntimeError(f"{label} result is not a JSON list: {path}")

    incomplete = []
    invalid_sample_ids = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            incomplete.append(f"<invalid-row-{index}>")
            invalid_sample_ids.append(f"row-{index}")
            continue
        diagnosis = row.get("diagnosis")
        if row.get("status") != "success" or not isinstance(diagnosis, dict):
            incomplete.append(str(row.get("sample_id") or "<missing-sample-id>"))
        sample_id = row.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id.strip():
            invalid_sample_ids.append(f"row-{index}")

    sample_ids = [row["sample_id"] for row in rows if isinstance(row, dict) and isinstance(row.get("sample_id"), str) and row["sample_id"].strip()]
    duplicate_ids = sorted(
        sample_id for sample_id, count in Counter(sample_ids).items() if count > 1
    )
    if len(rows) != expected_samples or incomplete or duplicate_ids or invalid_sample_ids:
        preview = ", ".join(incomplete[:12]) or "none"
        duplicate_preview = ", ".join(duplicate_ids[:12]) or "none"
        raise RuntimeError(
            f"{label} result is incomplete: rows={len(rows)}, "
            f"expected={expected_samples}, incomplete={len(incomplete)}, "
            f"samples={preview}, duplicate_ids={duplicate_preview}, "
            f"invalid_sample_ids={invalid_sample_ids[:12] or 'none'}. "
            f"Rerun --stage {label.lower()} until all expected samples succeed."
        )
    return set(sample_ids)


def validate_matching_sample_ids(
    base_ids: set[str],
    agent_ids: set[str],
    base_label: str = "KG",
    agent_label: str = "Agent",
) -> None:
    if base_ids == agent_ids:
        return
    missing_from_agent = sorted(base_ids - agent_ids)
    missing_from_base = sorted(agent_ids - base_ids)
    raise RuntimeError(
        f"{base_label} and {agent_label} sample IDs do not match. "
        f"missing_from_{agent_label.lower()}={missing_from_agent[:12]}, "
        f"missing_from_{base_label.lower()}={missing_from_base[:12]}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run KG-RAG, Agent, then Hybrid fusion."
    )
    parser.add_argument(
        "--stage",
        choices=("all", "kg", "agent", "fuse", "refine"),
        default="all",
        help="Run all stages or resume from an individual stage.",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        help="Dataset root shared by CVE and Sample_* inputs.",
    )
    parser.add_argument(
        "--experiment-name",
        default="",
        help="Isolate generated configs and outputs under outputs/<name>.",
    )
    parser.add_argument(
        "--expected-samples",
        type=int,
        help="Override the sample count inferred from --dataset-dir.",
    )
    parser.add_argument(
        "--graph-version",
        default="unspecified",
        help="Neo4j snapshot/version label recorded in the experiment manifest.",
    )
    parser.add_argument(
        "--upgrade-legacy-manifest",
        action="store_true",
        help="Upgrade an old manifest only when its saved configs match this run.",
    )
    args = parser.parse_args()

    python = sys.executable
    run([python, "verify_sources.py"], ROOT)

    base_kg_config = yaml.safe_load(
        (KG_DIR / "config.yaml").read_text(encoding="utf-8")
    )
    base_agent_config = yaml.safe_load(
        (AGENT_DIR / "config.yaml").read_text(encoding="utf-8")
    )
    dataset_dir = args.dataset_dir
    if dataset_dir is None:
        cve_dir = Path(base_agent_config["paths"]["cve_dir"])
        synthetic_dir = Path(base_agent_config["paths"]["synthetic_dir"])
        if cve_dir != synthetic_dir:
            raise ValueError(
                "The Hybrid runner requires one shared dataset directory; "
                "pass --dataset-dir explicitly."
            )
        dataset_dir = cve_dir
    dataset_dir = dataset_dir.expanduser().resolve()

    output_root = resolve_output_root(args.experiment_name)

    dataset_samples = discover_dataset_samples(dataset_dir)
    if not dataset_samples:
        raise RuntimeError(f"No supported samples found in dataset directory: {dataset_dir}")
    expected_sample_ids = set(dataset_samples)
    expected_samples = len(expected_sample_ids)
    if args.expected_samples is not None and args.expected_samples != expected_samples:
        raise ValueError(
            f"--expected-samples={args.expected_samples} does not match "
            f"the {expected_samples} loadable samples in {dataset_dir}"
        )
    config_root = output_root / "configs"
    kg_config = config_root / "kg.yaml"
    agent_config = config_root / "agent.yaml"
    kg_effective_config, agent_effective_config, should_write_configs = (
        select_effective_configs(
            args.stage,
            base_kg_config,
            base_agent_config,
            dataset_dir,
            output_root,
        )
    )
    if args.experiment_name:
        ensure_dataset_manifest(
            output_root,
            dataset_dir,
            dataset_samples,
            config_hashes={
                "kg": config_digest(kg_effective_config),
                "agent": config_digest(agent_effective_config),
            },
            graph_version=args.graph_version,
            upgrade_legacy=args.upgrade_legacy_manifest,
        )
    if should_write_configs:
        write_experiment_config(
            KG_DIR / "config.yaml",
            kg_config,
            dataset_dir,
            output_root / "kg",
        )
        write_experiment_config(
            AGENT_DIR / "config.yaml",
            agent_config,
            dataset_dir,
            output_root / "agent",
        )

    print(f"[historical-hybrid] dataset={dataset_dir}")
    print(f"[historical-hybrid] expected_samples={expected_samples}")
    print(f"[historical-hybrid] output_root={output_root}")

    kg_result = output_root / "kg" / "detection_results_kg_rag.json"
    agent_result = (
        output_root / "agent" / "detection_results_agent_kg_rag.json"
    )
    hybrid_output = output_root / "hybrid"
    hybrid_result = hybrid_output / "detection_results_hybrid_kg_agent.json"
    refined_output = output_root / "hybrid_cwe_refined"

    # Historical KG code assumes its configured output directory already exists.
    kg_result.parent.mkdir(parents=True, exist_ok=True)
    agent_result.parent.mkdir(parents=True, exist_ok=True)
    hybrid_output.mkdir(parents=True, exist_ok=True)
    refined_output.mkdir(parents=True, exist_ok=True)

    if args.stage in {"all", "kg"}:
        run(
            [python, "main_offline.py", "--config", str(kg_config)],
            KG_DIR,
        )

    if args.stage in {"all", "agent"}:
        run(
            [
                python,
                "main_agent_offline.py",
                "--config",
                str(agent_config),
            ],
            AGENT_DIR,
        )

    if args.stage in {"all", "fuse"}:
        missing = [path for path in (kg_result, agent_result) if not path.exists()]
        if missing:
            joined = ", ".join(str(path) for path in missing)
            raise FileNotFoundError(f"Missing upstream result files: {joined}")
        kg_ids = validate_result_file(kg_result, "KG", expected_samples)
        agent_ids = validate_result_file(agent_result, "Agent", expected_samples)
        validate_matching_sample_ids(expected_sample_ids, kg_ids, "Dataset", "KG")
        validate_matching_sample_ids(expected_sample_ids, agent_ids, "Dataset", "Agent")
        validate_matching_sample_ids(kg_ids, agent_ids)
        run(
            [
                python,
                "hybrid_fuse_results.py",
                "--base",
                str(kg_result),
                "--agent",
                str(agent_result),
                "--output-dir",
                str(hybrid_output),
            ],
            ROOT,
        )
        hybrid_ids = validate_result_file(hybrid_result, "Hybrid", expected_samples)
        validate_matching_sample_ids(expected_sample_ids, hybrid_ids, "Dataset", "Hybrid")

    if args.stage == "refine":
        if not hybrid_result.exists():
            raise FileNotFoundError(f"Missing Hybrid result file: {hybrid_result}")
        hybrid_ids = validate_result_file(hybrid_result, "Hybrid", expected_samples)
        validate_matching_sample_ids(expected_sample_ids, hybrid_ids, "Dataset", "Hybrid")
        run(
            [
                python,
                "hybrid_cwe_refine_offline.py",
                "--input",
                str(hybrid_result),
                "--config",
                str(agent_config),
                "--output-dir",
                str(refined_output),
            ],
            ROOT,
        )


if __name__ == "__main__":
    main()
