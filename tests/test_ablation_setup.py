"""Check ablation configuration and real execution boundaries without a GPU."""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
NO_KG = ROOT / 'ablations/without_kg'


class AblationSetupTests(unittest.TestCase):
    def test_example_configs_select_distinct_modes_and_outputs(self):
        configs = [yaml.safe_load(path.read_text(encoding='utf-8')) for path in (
            ROOT/'ablations/base_llm.example.yaml',
            ROOT/'ablations/without_agent.example.yaml',
            NO_KG/'config.example.yaml')]
        self.assertEqual([c['experiment']['pipeline_mode'] for c in configs],
                         ['base_llm', 'kg_rag', 'unified_agent_without_kg'])
        self.assertEqual(len({c['paths']['output_dir'] for c in configs}), 3)
        for config in (configs[0], configs[2]):
            self.assertNotIn('neo4j', config)
            self.assertNotIn('embedding', config['llm'])
        self.assertEqual(configs[1]['neo4j']['password'], 'CHANGE_ME')

    def test_code_only_active_entrypoint_cannot_call_legacy_kg_helpers(self):
        forbidden = {'query_graph_warnings', 'SemanticSimilarityModel', 'GraphDatabase'}
        tree = ast.parse((NO_KG/'main_agent_offline.py').read_text(encoding='utf-8-sig'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, 'attr', getattr(node.func, 'id', ''))
                self.assertNotIn(name, forbidden)
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    self.assertNotEqual((node.func.value.id, node.func.attr), ('offline', 'main'))
        for path in NO_KG.glob('*.py'):
            tree = ast.parse(path.read_text(encoding='utf-8-sig'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(item.name.split('.')[0] != 'neo4j' for item in node.names))
                if isinstance(node, ast.ImportFrom):
                    self.assertNotEqual((node.module or '').split('.')[0], 'neo4j')

    def test_code_only_dependency_closure_includes_binary_recovery(self):
        self.assertTrue((NO_KG/'historical_binary_recovery.py').is_file())
        local = {'schemas', 'agent_schemas', 'data_loader', 'offline_runtime',
                 'decision_policy', 'global_checkpoint', 'historical_binary_recovery',
                 'llm_compat', 'evaluate'}
        for path in NO_KG.glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text(encoding='utf-8-sig'))):
                if isinstance(node, ast.ImportFrom) and node.module in local:
                    self.assertTrue((NO_KG/(node.module+'.py')).is_file(), node.module)
                if isinstance(node, ast.Import):
                    for item in node.names:
                        if item.name in local:
                            self.assertTrue((NO_KG/(item.name+'.py')).is_file(), item.name)

    def test_base_llm_runs_original_pipeline_without_graph_or_embeddings(self):
        # Run the actual copied main in a child interpreter: module names such
        # as schemas cannot leak between independent original experiments.
        script = r'''
import json, runpy, sys, types
from pathlib import Path
root, config = map(Path, sys.argv[1:])
def forbidden(*args, **kwargs):
    raise AssertionError('Base-LLM attempted external knowledge access')
transformers = types.ModuleType('transformers'); transformers.__path__ = []
for name in ['tokenization_utils', 'tokenization_utils_base']:
    module = types.ModuleType('transformers.'+name)
    setattr(transformers, name, module); sys.modules[module.__name__] = module
transformers.AutoTokenizer = types.SimpleNamespace(from_pretrained=forbidden)
transformers.AutoModel = types.SimpleNamespace(from_pretrained=forbidden)
sys.modules['transformers'] = transformers
sys.modules['neo4j'] = types.SimpleNamespace(GraphDatabase=types.SimpleNamespace(driver=forbidden))
class Engine:
    stages = []
    def __init__(self, **kwargs): pass
    def chat(self, conversations, **kwargs):
        result = []
        for conversation in conversations:
            prompt = conversation[0]['content']
            if 'code_logic_analysis' in prompt and 'is_vulnerable' in prompt:
                stage = 'binary'
                data = dict(is_vulnerable=True, confidence=.9,
                    graph_warning_critique='No KG', code_logic_analysis='Fixture')
            elif 'Candidate CWE Pool' in prompt:
                stage = 'cwe'; data = dict(cwe_id='CWE-120', vulnerability_type='Fixture')
            elif 'affected_lines' in prompt:
                stage = 'report'; data = dict(explanation='Fixture', affected_lines=[])
            else:
                raise AssertionError('Unexpected extraction or graph conversation')
            self.stages.append(stage)
            result.append(types.SimpleNamespace(outputs=[types.SimpleNamespace(text=json.dumps(data))]))
        return result
sys.modules['vllm'] = types.SimpleNamespace(LLM=Engine, SamplingParams=lambda **kw: types.SimpleNamespace(**kw))
sys.path.insert(0, str(root/'kg'))
sys.argv = ['main_offline.py', '--config', str(config)]
runpy.run_path(str(root/'kg/main_offline.py'), run_name='__main__')
assert Engine.stages == ['binary', 'cwe', 'report'], Engine.stages
'''
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); dataset = base/'dataset'; sample = dataset/'CVE-2026-0001'
            sample.mkdir(parents=True)
            (sample/'vuln_code.md').write_text('```cpp\nvoid f() { copy(dst, src); }\n```', encoding='utf-8')
            (sample/'vuln_info.json').write_text(json.dumps({'cwe_id': 'CWE-120'}), encoding='utf-8')
            output = base/'output'; output.mkdir()
            config = yaml.safe_load((ROOT/'ablations/base_llm.example.yaml').read_text(encoding='utf-8'))
            config['paths'].update(cve_dir=str(dataset), synthetic_dir=str(dataset), output_dir=str(output))
            path = base/'config.yaml'; path.write_text(yaml.safe_dump(config), encoding='utf-8')
            env = os.environ.copy(); env['PYTHONDONTWRITEBYTECODE'] = '1'
            process = subprocess.run([sys.executable, '-B', '-c', script, str(ROOT), str(path)],
                                     capture_output=True, text=True, encoding='utf-8', env=env, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr+'\n'+process.stdout)
            rows = json.loads((output/'detection_results_base_llm.json').read_text(encoding='utf-8'))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['status'], 'success')
            self.assertEqual(rows[0]['graph_warnings'], [])


if __name__ == '__main__':
    unittest.main()
