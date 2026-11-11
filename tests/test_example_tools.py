import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ExampleToolsTests(unittest.TestCase):
    def test_expected_graph_identity_detects_changed_properties_not_only_counts(self):
        import copy
        from scripts.load_example_graph import expected_fixture_snapshot, canonical_snapshot, assert_fixture_snapshot
        fixture = expected_fixture_snapshot()
        assert_fixture_snapshot(fixture)
        changed = copy.deepcopy(fixture)
        changed['nodes'][0]['properties']['name'] = 'altered content'
        with self.assertRaisesRegex(ValueError, 'contents differ'):
            assert_fixture_snapshot(canonical_snapshot(changed))

    def test_graph_import_refuses_non_example_nodes(self):
        from scripts.load_example_graph import import_fixture
        class Driver:
            calls = []
            def session(self, **kw): return self
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def run(self, query, **kw):
                self.calls.append(query)
                return self
            def single(self): return {'count': 1}
        driver = Driver()
        with self.assertRaisesRegex(ValueError, 'non-example'):
            import_fixture(driver, 'neo4j', 'MERGE (:OGVulExample)')
        self.assertEqual(len(driver.calls), 1)

    def test_example_preparation_isolated_and_never_overwrites_a_run(self):
        from scripts.run_example import prepare_run
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            model = base/'model'; model.mkdir()
            bge = base/'bge'; bge.mkdir()
            config = dict(model_path=str(model), embedding_path=str(bge),
                graph=dict(uri='bolt://127.0.0.1:7689', database='neo4j',
                           username='neo4j', password_env='OGVUL_TEST_PASSWORD'),
                engine=dict(gpu_memory_utilization=.8, tensor_parallel_size=1))
            with patch.dict(os.environ, OGVUL_TEST_PASSWORD='fixture-only'):
                prepared = prepare_run(config, 'demo', base/'runs')
                with self.assertRaises(FileExistsError):
                    prepare_run(config, 'demo', base/'runs')
            workspace = Path(prepared['workspace'])
            kg = yaml.safe_load((workspace/'kg/config.yaml').read_text())
            self.assertEqual(kg['neo4j']['password'], 'fixture-only')
            self.assertEqual(Path(kg['llm']['embedding']['model_path']), bge)
            self.assertEqual(kg['llm']['extraction']['max_tokens'], 1024)
            self.assertEqual(Path(prepared['run_root']).parent, base/'runs')
            for value in ['../escape', '/absolute', 'nested/name']:
                with self.assertRaises(ValueError):
                    prepare_run(config, value, base/'runs')


if __name__ == '__main__':
    unittest.main()
