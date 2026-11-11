from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import run_historical_hybrid as runner


class HistoricalHybridRunnerTests(unittest.TestCase):
    def test_count_dataset_samples_counts_both_variants_of_sample_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset = Path(temp_dir)
            sample = dataset / "Sample_CWE125_001"
            sample.mkdir()
            (sample / "mutated_code.cpp").write_text("bad", encoding="utf-8")
            (sample / "safe_code.cpp").write_text("good", encoding="utf-8")
            cve = dataset / "CVE-2024-0001"
            cve.mkdir()
            (cve / "vuln_code.md").write_text("```cpp\nbad();\n```", encoding="utf-8")
            fixed = dataset / "CVE-2024-0001-fixed"
            fixed.mkdir()
            (fixed / "vuln_code.md").write_text("```cpp\ngood();\n```", encoding="utf-8")

            self.assertEqual(runner.count_dataset_samples(dataset), 4)

    def test_discover_dataset_samples_skips_inputs_the_loader_cannot_read(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dataset = Path(temp_dir)
            (dataset / "Sample_CWE125_001").mkdir()
            (dataset / "CVE-2024-0001").mkdir()

            self.assertEqual(runner.discover_dataset_samples(dataset), {})

    def test_build_experiment_config_isolates_dataset_and_output_paths(self):
        base_config = {
            "paths": {
                "cve_dir": "/old/data",
                "synthetic_dir": "/old/data",
                "output_dir": "/old/output",
            }
        }

        configured = runner.build_experiment_config(
            base_config,
            Path("/datasets/example-pairs"),
            Path("/runs/example-pairs/kg"),
        )

        self.assertEqual(configured["paths"]["cve_dir"], "/datasets/example-pairs")
        self.assertEqual(configured["paths"]["synthetic_dir"], "/datasets/example-pairs")
        self.assertEqual(
            configured["paths"]["output_dir"],
            "/runs/example-pairs/kg",
        )
        self.assertEqual(base_config["paths"]["cve_dir"], "/old/data")

    def test_fuse_reuses_saved_stage_configs_instead_of_current_base_configs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "outputs" / "64pairs"
            config_root = output_root / "configs"
            config_root.mkdir(parents=True)
            saved_kg = {"model": "original-kg", "paths": {"output_dir": "/saved/kg"}}
            saved_agent = {
                "model": "original-agent",
                "paths": {"output_dir": "/saved/agent"},
            }
            (config_root / "kg.yaml").write_text(
                runner.yaml.safe_dump(saved_kg), encoding="utf-8"
            )
            (config_root / "agent.yaml").write_text(
                runner.yaml.safe_dump(saved_agent), encoding="utf-8"
            )

            kg_config, agent_config, should_write = runner.select_effective_configs(
                "fuse",
                {"model": "changed-kg"},
                {"model": "changed-agent"},
                Path("/dataset"),
                output_root,
            )

            self.assertEqual(kg_config, saved_kg)
            self.assertEqual(agent_config, saved_agent)
            self.assertFalse(should_write)

    def test_validate_matching_sample_ids_rejects_different_inputs(self):
        with self.assertRaisesRegex(RuntimeError, "sample IDs do not match"):
            runner.validate_matching_sample_ids(
                {"CVE-1", "Sample_CWE125_001_vuln"},
                {"CVE-1", "Sample_CWE125_001_safe"},
            )

    def test_resolve_output_root_rejects_path_traversal(self):
        for unsafe_name in ("../escape", "nested/name", "C:\\escape"):
            with self.subTest(unsafe_name=unsafe_name):
                with self.assertRaisesRegex(ValueError, "safe name"):
                    runner.resolve_output_root(unsafe_name)

    def test_dataset_manifest_rejects_changed_code_for_existing_experiment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "outputs" / "64pairs"
            output_root.mkdir(parents=True)
            runner.ensure_dataset_manifest(
                output_root,
                Path("/dataset"),
                {"sample-1": "hash-a"},
            )

            with self.assertRaisesRegex(RuntimeError, "dataset content changed"):
                runner.ensure_dataset_manifest(
                    output_root,
                    Path("/dataset"),
                    {"sample-1": "hash-b"},
                )

    def test_dataset_manifest_rejects_nonempty_untracked_experiment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "outputs" / "64pairs"
            output_root.mkdir(parents=True)
            (output_root / "old-result.json").write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "has no dataset manifest"):
                runner.ensure_dataset_manifest(
                    output_root,
                    Path("/dataset"),
                    {"sample-1": "hash-a"},
                )

    def test_dataset_manifest_rejects_changed_effective_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "outputs" / "64pairs"
            output_root.mkdir(parents=True)
            runner.ensure_dataset_manifest(
                output_root,
                Path("/dataset"),
                {"sample-1": "hash-a"},
                config_hashes={"kg": "config-a", "agent": "config-a"},
                graph_version="neo4j-20260928",
            )

            with self.assertRaisesRegex(RuntimeError, "configuration changed"):
                runner.ensure_dataset_manifest(
                    output_root,
                    Path("/dataset"),
                    {"sample-1": "hash-a"},
                    config_hashes={"kg": "config-b", "agent": "config-a"},
                    graph_version="neo4j-20260928",
                )

    def test_legacy_manifest_can_be_explicitly_upgraded_when_saved_configs_match(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "outputs" / "64pairs"
            config_root = output_root / "configs"
            config_root.mkdir(parents=True)
            kg_config = {"paths": {"output_dir": "/output/kg"}, "model": "qwen"}
            agent_config = {"paths": {"output_dir": "/output/agent"}, "model": "qwen"}
            (config_root / "kg.yaml").write_text(
                runner.yaml.safe_dump(kg_config), encoding="utf-8"
            )
            (config_root / "agent.yaml").write_text(
                runner.yaml.safe_dump(agent_config), encoding="utf-8"
            )
            legacy_manifest = {
                "version": 1,
                "dataset_dir": "/dataset",
                "sample_count": 1,
                "samples": {"sample-1": "hash-a"},
            }
            (output_root / "dataset_manifest.json").write_text(
                json.dumps(legacy_manifest), encoding="utf-8"
            )

            runner.ensure_dataset_manifest(
                output_root,
                Path("/dataset"),
                {"sample-1": "hash-a"},
                config_hashes={
                    "kg": runner.config_digest(kg_config),
                    "agent": runner.config_digest(agent_config),
                },
                graph_version="current-neo4j-20260928",
                upgrade_legacy=True,
            )

            upgraded = json.loads(
                (output_root / "dataset_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(upgraded["graph_version"], "current-neo4j-20260928")
            self.assertEqual(
                upgraded["config_hashes"]["kg"],
                runner.config_digest(kg_config),
            )

    def test_legacy_manifest_can_add_graph_label_when_config_hashes_already_exist(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "outputs" / "64pairs"
            config_root = output_root / "configs"
            config_root.mkdir(parents=True)
            kg_config = {"model": "kg"}
            agent_config = {"model": "agent"}
            config_hashes = {
                "kg": runner.config_digest(kg_config),
                "agent": runner.config_digest(agent_config),
            }
            (config_root / "kg.yaml").write_text(
                runner.yaml.safe_dump(kg_config), encoding="utf-8"
            )
            (config_root / "agent.yaml").write_text(
                runner.yaml.safe_dump(agent_config), encoding="utf-8"
            )
            (output_root / "dataset_manifest.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "samples": {"sample-1": "hash-a"},
                        "config_hashes": config_hashes,
                        "graph_version": "unspecified",
                    }
                ),
                encoding="utf-8",
            )

            runner.ensure_dataset_manifest(
                output_root,
                Path("/dataset"),
                {"sample-1": "hash-a"},
                config_hashes=config_hashes,
                graph_version="current-neo4j-20260928",
                upgrade_legacy=True,
            )

            upgraded = json.loads(
                (output_root / "dataset_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(upgraded["graph_version"], "current-neo4j-20260928")

    def test_validate_result_file_uses_requested_sample_count(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = Path(temp_dir) / "result.json"
            rows = [
                {
                    "sample_id": f"sample-{index}",
                    "status": "success",
                    "diagnosis": {"is_vulnerable": False},
                }
                for index in range(3)
            ]
            result_path.write_text(json.dumps(rows), encoding="utf-8")

            sample_ids = runner.validate_result_file(result_path, "KG", expected_samples=3)

            self.assertEqual(sample_ids, {"sample-0", "sample-1", "sample-2"})

    def test_validate_result_file_rejects_empty_sample_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = Path(temp_dir) / "result.json"
            result_path.write_text(
                json.dumps(
                    [{"sample_id": "", "status": "success", "diagnosis": {}}]
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "invalid_sample_ids"):
                runner.validate_result_file(result_path, "KG", expected_samples=1)


if __name__ == "__main__":
    unittest.main()
