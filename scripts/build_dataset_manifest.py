"""Build integrity metadata for an OGVul-format dataset without copying source code.

The manifest deliberately follows ``kg/data_loader.py`` so its ordering and labels
match the experiment input semantics.  It has no model, GPU, or graph dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
KG_DIR = REPOSITORY_ROOT / "kg"


@contextmanager
def _original_loader() -> Iterator[type]:
    """Load the selected loader in a temporary module namespace.

    ``data_loader.py`` imports ``schemas`` by its historical absolute name.  Save
    and restore those names so this tool cannot accidentally use similarly named
    modules from another OGVul pipeline.
    """
    saved = {name: sys.modules.get(name) for name in ("schemas", "data_loader")}
    inserted_path = str(KG_DIR)
    sys.path.insert(0, inserted_path)
    try:
        for name in saved:
            sys.modules.pop(name, None)
        for name in ("schemas", "data_loader"):
            spec = importlib.util.spec_from_file_location(name, KG_DIR / f"{name}.py")
            if spec is None or spec.loader is None:
                raise RuntimeError(f"Cannot load original module: {name}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        yield sys.modules["data_loader"].DataLoader
    finally:
        for name in saved:
            sys.modules.pop(name, None)
            if saved[name] is not None:
                sys.modules[name] = saved[name]
        try:
            sys.path.remove(inserted_path)
        except ValueError:
            pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_file_hashes(dataset_path: Path, sample_id: str, source_type: str) -> dict[str, str]:
    if source_type.startswith("cve_"):
        directory = dataset_path / sample_id
        names = ("vuln_code.md", "vuln_info.json")
    else:
        directory = dataset_path / sample_id.rsplit("_", 1)[0]
        names = (
            "mutated_code.cpp" if source_type == "synthetic_vuln" else "safe_code.cpp",
            "vuln_info.json",
        )
    return {
        file_path.relative_to(dataset_path).as_posix(): _sha256(file_path)
        for name in names
        if (file_path := directory / name).is_file()
    }


def _list_cwe_annotations(dataset_path: Path) -> dict[str, list]:
    """Find list-valued annotations and map them to their logical sample IDs."""
    affected: dict[str, list] = {}
    for directory in dataset_path.iterdir() if dataset_path.is_dir() else ():
        annotation = directory / "vuln_info.json"
        if not directory.is_dir() or not annotation.is_file():
            continue
        try:
            value = json.loads(annotation.read_text(encoding="utf-8")).get("cwe_id")
        except json.JSONDecodeError:
            continue
        if not isinstance(value, list):
            continue
        if directory.name.startswith("CVE-"):
            affected[directory.name] = value
        elif directory.name.startswith("Sample_"):
            affected[f"{directory.name}_vuln"] = value
            affected[f"{directory.name}_safe"] = value
    return affected


def build_manifest(dataset_path: Path, *, normalize_cwe_lists: bool = False) -> dict:
    """Return a manifest using the original loader; normalization is opt-in inventory support.

    With its default arguments this calls the loader exactly as checked in.  A
    dataset with list-valued ``cwe_id`` annotations therefore fails exactly as
    the current ``SampleInfo`` schema fails.  Opt-in normalization exists only
    to inventory that historical data without editing it.
    """
    dataset_path = Path(dataset_path).resolve()
    list_annotations = _list_cwe_annotations(dataset_path)
    with _original_loader() as data_loader:
        if normalize_cwe_lists:
            # This preserves discovery, ordering, and code extraction.  A
            # singleton list can be unwrapped for the string schema.  For a
            # multi-value list no CWE is selected: an empty private value only
            # lets the loader enumerate the sample, while the manifest keeps
            # the original list verbatim below.
            read_cwe_id = data_loader._read_cwe_id

            def normalized_cwe_id(json_path: Path) -> str:
                value = read_cwe_id(json_path)
                if isinstance(value, list):
                    return str(value[0]) if len(value) == 1 else ""
                return "" if value is None else str(value)

            data_loader._read_cwe_id = staticmethod(normalized_cwe_id)
        loaded = data_loader(str(dataset_path), str(dataset_path)).load_all()

    samples: dict[str, dict] = {}
    load_order: list[str] = []
    counts: dict[str, int] = {}
    for sample in loaded:
        if sample.sample_id in samples:
            raise ValueError(f"Duplicate sample ID from loader: {sample.sample_id}")
        source_type = sample.source_type
        original_list = list_annotations.get(sample.sample_id)
        samples[sample.sample_id] = {
            "label": sample.label,
            "cwe_id": original_list if original_list is not None else sample.cwe_id,
            "source_type": source_type,
            "code_sha256": hashlib.sha256(sample.code.encode("utf-8")).hexdigest(),
            "files": _relative_file_hashes(dataset_path, sample.sample_id, source_type),
        }
        load_order.append(sample.sample_id)
        counts[source_type] = counts.get(source_type, 0) + 1

    affected_samples = {
        sample_id: {
            "original_cwe_id": value,
            "inventory_cwe_id": value,
            "loader_value_used": str(value[0]) if len(value) == 1 else "",
        }
        for sample_id, value in list_annotations.items()
        if sample_id in samples
    }
    return {
        "sample_count": len(load_order),
        "counts": counts,
        "load_order": load_order,
        "samples": samples,
        "loader_compatible": not bool(affected_samples),
        "annotation_normalization": {
            "enabled": normalize_cwe_lists,
            "purpose": "inventory only; source annotations were not modified",
            "single_value_rule": "A one-item cwe_id list is unwrapped only for the loader boundary.",
            "multiple_value_rule": "A multi-item cwe_id list is retained verbatim; no CWE is selected. An empty private loader value is used only to enumerate the sample.",
            "affected_samples": affected_samples,
        },
    }


def verify_manifest(dataset_path: Path, manifest_path: Path, *, normalize_cwe_lists: bool = False) -> list[str]:
    """Return a compact list of differences; an empty list means verification passed."""
    manifest_path = Path(manifest_path)
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_normalization = bool(expected.get("annotation_normalization", {}).get("enabled"))
    if expected_normalization != normalize_cwe_lists:
        option = "requires" if expected_normalization else "does not use"
        return [f"manifest {option} --normalize-cwe-lists"]
    actual = build_manifest(Path(dataset_path), normalize_cwe_lists=normalize_cwe_lists)
    if actual == expected:
        return []
    differences: list[str] = []
    for key in ("sample_count", "counts", "load_order", "loader_compatible", "annotation_normalization"):
        if actual.get(key) != expected.get(key):
            differences.append(f"{key} differs")
    expected_samples = expected.get("samples", {})
    actual_samples = actual["samples"]
    for sample_id in sorted(set(expected_samples) | set(actual_samples)):
        if expected_samples.get(sample_id) != actual_samples.get(sample_id):
            differences.append(f"sample differs: {sample_id}")
    return differences or ["manifest differs"]


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True, help="Dataset root used for both loader inputs")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path, help="New manifest path")
    action.add_argument("--verify", type=Path, metavar="MANIFEST", help="Verify an existing manifest")
    parser.add_argument("--force", action="store_true", help="Allow replacing an existing output file")
    parser.add_argument(
        "--normalize-cwe-lists",
        action="store_true",
        help="Explicitly inventory list-valued CWE annotations without modifying source data",
    )
    args = parser.parse_args()

    if args.verify:
        differences = verify_manifest(args.dataset, args.verify, normalize_cwe_lists=args.normalize_cwe_lists)
        if differences:
            print("Verification failed: " + "; ".join(differences))
            return 1
        print("Verification passed.")
        return 0

    output = args.output.resolve()
    if _is_within(output, args.dataset):
        parser.error("Refusing to write a manifest inside the dataset root")
    if output.exists() and not args.force:
        parser.error(f"Output already exists: {output} (use --force to replace it)")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(args.dataset, normalize_cwe_lists=args.normalize_cwe_lists)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
