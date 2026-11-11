from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY_ROOT / "scripts" / "build_dataset_manifest.py"
SPEC = importlib.util.spec_from_file_location("build_dataset_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MANIFEST_TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST_TOOL)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _fixture_dataset(root: Path) -> None:
    _write(root / "CVE-2024-0002" / "vuln_code.md", "# sample\n```cpp\nint vulnerable_two;\n```\n")
    _write(root / "CVE-2024-0002" / "vuln_info.json", '{"cwe_id": "CWE-787"}')
    _write(root / "CVE-2024-0001" / "vuln_code.md", "```c\nint vulnerable_one;\n```\n")
    _write(root / "CVE-2024-0001-fixed" / "vuln_code.md", "```c\nint fixed_one;\n```\n")
    _write(root / "Sample_CWE22_002" / "mutated_code.cpp", "int second_mutated;\n")
    _write(root / "Sample_CWE22_002" / "safe_code.cpp", "int second_safe;\n")
    _write(root / "Sample_CWE22_002" / "vuln_info.json", '{"cwe_id": "CWE-22"}')
    _write(root / "Sample_CWE22_001" / "mutated_code.cpp", "int first_mutated;\n")
    _write(root / "Sample_CWE22_001" / "safe_code.cpp", "int first_safe;\n")


class DatasetMaterialsTests(unittest.TestCase):
    def test_loader_order_and_manifest_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / "dataset"
            _fixture_dataset(dataset)
            manifest = MANIFEST_TOOL.build_manifest(dataset)

            self.assertEqual(manifest["sample_count"], 7)
            self.assertEqual(
                manifest["load_order"],
                [
                    "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0001-fixed",
                    "Sample_CWE22_001_vuln", "Sample_CWE22_002_vuln",
                    "Sample_CWE22_001_safe", "Sample_CWE22_002_safe",
                ],
            )
            self.assertEqual(
                manifest["counts"],
                {"cve_vuln": 2, "cve_fixed": 1, "synthetic_vuln": 2, "synthetic_safe": 2},
            )
            sample = manifest["samples"]["Sample_CWE22_002_vuln"]
            self.assertEqual(sample["label"], "vulnerable")
            self.assertEqual(sample["cwe_id"], "CWE-22")
            self.assertIn("Sample_CWE22_002/mutated_code.cpp", sample["files"])

    def test_manifest_excludes_code_and_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / "dataset"
            _fixture_dataset(dataset)
            manifest = MANIFEST_TOOL.build_manifest(dataset)
            rendered = json.dumps(manifest)
            self.assertNotIn("int vulnerable_two", rendered)
            self.assertNotIn(str(dataset), rendered)
            for sample in manifest["samples"].values():
                self.assertEqual(set(sample), {"label", "cwe_id", "source_type", "code_sha256", "files"})
                for relative_name in sample["files"]:
                    self.assertFalse(Path(relative_name).is_absolute())

    def test_list_annotations_fail_by_default_and_are_explicitly_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / "dataset"
            _fixture_dataset(dataset)
            _write(dataset / "CVE-2024-0002" / "vuln_info.json", '{"cwe_id": ["CWE-120", "CWE-121"]}')
            with self.assertRaises(Exception):
                MANIFEST_TOOL.build_manifest(dataset)
            manifest = MANIFEST_TOOL.build_manifest(dataset, normalize_cwe_lists=True)
            self.assertFalse(manifest["loader_compatible"])
            self.assertTrue(manifest["annotation_normalization"]["enabled"])
            record = manifest["annotation_normalization"]["affected_samples"]["CVE-2024-0002"]
            self.assertEqual(record["original_cwe_id"], ["CWE-120", "CWE-121"])
            self.assertEqual(record["loader_value_used"], "")
            self.assertEqual(manifest["samples"]["CVE-2024-0002"]["cwe_id"], ["CWE-120", "CWE-121"])

    def test_verification_detects_code_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "dataset"
            _fixture_dataset(dataset)
            stored = root / "manifest.json"
            stored.write_text(json.dumps(MANIFEST_TOOL.build_manifest(dataset)), encoding="utf-8")
            _write(dataset / "Sample_CWE22_001" / "mutated_code.cpp", "int changed;\n")
            differences = MANIFEST_TOOL.verify_manifest(dataset, stored)
            self.assertTrue(any("Sample_CWE22_001_vuln" in item for item in differences))

    def test_checked_in_manifest_and_third_party_placeholder(self) -> None:
        manifest_path = REPOSITORY_ROOT / "data" / "paper_manifest.json"
        self.assertTrue(manifest_path.is_file())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["sample_count"], 280)
        self.assertEqual(
            manifest["counts"],
            {"cve_vuln": 55, "cve_fixed": 25, "synthetic_vuln": 100, "synthetic_safe": 100},
        )
        self.assertFalse(manifest["loader_compatible"])
        affected = manifest["annotation_normalization"]["affected_samples"]
        self.assertEqual(len(affected), 4)
        third_party = REPOSITORY_ROOT / "data" / "third_party_samples"
        self.assertEqual(
            {path.name for path in third_party.rglob("*") if path.is_file()},
            {"README.md", "sample_origin.example.yaml"},
        )


if __name__ == "__main__":
    unittest.main()
