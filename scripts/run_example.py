# SPDX-License-Identifier: MIT
"""Run the unchanged original inference entrypoint in an isolated example workspace."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def prepare_run(config, run_name, output_root=None):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', run_name):
        raise ValueError('Use a simple run name without directories')
    models = {}
    for key in ('model_path', 'embedding_path'):
        path = Path(config[key]).expanduser().resolve()
        if not path.is_dir():
            raise ValueError(f'Configure an existing local directory for {key}')
        models[key] = path
    profile = config.get('engine', {})
    fraction = profile.get('gpu_memory_utilization', .8)
    parallel = profile.get('tensor_parallel_size', 1)
    if isinstance(fraction, bool) or not 0 < fraction < 1:
        raise ValueError('gpu_memory_utilization must be between zero and one')
    if type(parallel) is not int or parallel < 1:
        raise ValueError('tensor_parallel_size must be a positive integer')
    from scripts.load_example_graph import graph_connection
    graph, auth = graph_connection(config)
    output_root = Path(output_root or ROOT/'outputs').resolve()
    run_root = output_root/run_name
    if run_root.exists():
        raise FileExistsError('Choose a new run name; example runs never overwrite existing files')
    source_manifest = json.loads((ROOT/'source_manifest.json').read_text(encoding='utf-8'))
    for relative, expected in source_manifest.items():
        source = (ROOT/relative).resolve()
        if not source.is_relative_to(ROOT.resolve()) or sha(source) != expected:
            raise ValueError(f'Source identity mismatch: {relative}')
    run_root.mkdir(parents=True, mode=0o700)
    workspace = run_root/'workspace'; workspace.mkdir()
    for relative in source_manifest:
        destination = workspace/relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/relative, destination)
    shutil.copyfile(ROOT/'source_manifest.json', workspace/'source_manifest.json')
    for branch in ('kg', 'agent'):
        settings = yaml.safe_load((ROOT/branch/'config.example.yaml').read_text(encoding='utf-8'))
        for phase in ('extraction', 'diagnosis'):
            settings['llm'][phase].update(model_path=str(models['model_path']),
                gpu_memory_utilization=fraction, tensor_parallel_size=parallel)
        settings['llm']['embedding']['model_path'] = str(models['embedding_path'])
        settings['neo4j'] = dict(uri=graph['uri'], database=graph.get('database', 'neo4j'),
            username=auth[0] if auth else 'neo4j', password=auth[1] if auth else '')
        path = workspace/branch/'config.yaml'
        path.write_text(yaml.safe_dump(settings, sort_keys=False), encoding='utf-8')
        path.chmod(0o600)
    return dict(run_root=str(run_root), workspace=str(workspace),
                dataset=str(ROOT/'examples/samples'), output=str(workspace/'outputs/example'))


def resource_identity(path):
    """Content identity without recording private absolute deployment paths."""
    path = Path(path)
    files = {}
    for item in sorted(path.rglob('*')):
        relative = item.relative_to(path)
        if item.is_file() and not item.is_symlink() and not any(p.startswith('.') for p in relative.parts):
            files[relative.as_posix()] = sha(item)
    encoded = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    return dict(algorithm='sha256-of-sorted-file-sha256-map', content_sha256=hashlib.sha256(encoded).hexdigest(), files=files)


def verify_outputs(output, ids):
    rows = {}
    names = dict(kg='detection_results_kg_rag.json', agent='detection_results_agent_kg_rag.json',
        hybrid='detection_results_hybrid_kg_agent.json', hybrid_cwe_refined='detection_results_hybrid_cwe_refined.json')
    for stage, name in names.items():
        data = json.loads((output/stage/name).read_text(encoding='utf-8'))
        if len(data) != len(ids) or {r['sample_id'] for r in data} != set(ids):
            raise ValueError(f'{stage} does not cover the selected samples')
        if any(r.get('status') != 'success' for r in data):
            raise ValueError(f'{stage} contains incomplete records')
        rows[stage] = {r['sample_id']: r for r in data}
    for sample in ids:
        baseline = rows['kg'][sample]['diagnosis']['is_vulnerable']
        if type(baseline) is not bool or any(rows[s][sample]['diagnosis']['is_vulnerable'] is not baseline
                                         for s in ('hybrid', 'hybrid_cwe_refined')):
            raise ValueError('Example fusion/refinement changed the Global binary verdict')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT/'examples/config.yaml')
    parser.add_argument('--run-name', default='example')
    parser.add_argument('--prepare-only', action='store_true', help='Prepare private configs without loading any model')
    args = parser.parse_args(argv)
    config = yaml.safe_load(args.config.read_text(encoding='utf-8'))
    prepared = prepare_run(config, args.run_name)
    run_root, workspace, output = (Path(prepared[k]) for k in ('run_root', 'workspace', 'output'))
    if args.prepare_only:
        print(run_root); return 0
    from scripts.build_dataset_manifest import build_manifest
    manifest = build_manifest(Path(prepared['dataset']))
    write_json(run_root/'dataset_manifest.json', manifest)
    identity = dict(status='running', started_at=datetime.now(timezone.utc).isoformat(),
        purpose='Original teaching example; not the paper benchmark', samples=manifest['sample_count'],
        source_files=json.loads((ROOT/'source_manifest.json').read_text(encoding='utf-8')),
        graph_fixture_sha256=sha(ROOT/'graph/example.cypher'),
        configuration=dict(model_path='${MODEL_DIR}', embedding_path='${EMBEDDING_DIR}',
            graph=dict(uri='${DEDICATED_EXAMPLE_GRAPH_URI}', database=config['graph'].get('database', 'neo4j'),
                       authentication='environment-variable' if config['graph'].get('password_env') else 'disabled-local-demo'),
            engine=copy.deepcopy(config.get('engine', {}))),
        runtime=dict(python=sys.version.split()[0], packages={name:importlib.metadata.version(name)
            for name in ('vllm', 'torch', 'transformers', 'neo4j', 'pydantic', 'PyYAML')}))
    write_json(run_root/'run_identity.json', identity)
    try:
        from scripts.load_example_graph import graph_connection, read_fixture_snapshot, assert_fixture_snapshot
        from neo4j import GraphDatabase
        graph, auth = graph_connection(config)
        with GraphDatabase.driver(graph['uri'], auth=auth) as driver:
            snapshot = read_fixture_snapshot(driver, graph.get('database', 'neo4j'))
        assert_fixture_snapshot(snapshot)
        identity['graph_content_sha256'] = snapshot['content_sha256']
        write_json(run_root/'graph_before.json', snapshot)
        write_json(run_root/'run_identity.json', identity)
        print('Hashing local model/embedding resources...', flush=True)
        identity['resources'] = {key:resource_identity(config[key]) for key in ('model_path', 'embedding_path')}
        write_json(run_root/'run_identity.json', identity)
        for stage in ('all', 'refine'):
            command = [sys.executable, '-B', str(workspace/'run_historical_hybrid.py'), '--stage', stage,
                '--dataset-dir', prepared['dataset'], '--experiment-name', 'example',
                '--graph-version', 'teaching-fixture-'+identity['graph_fixture_sha256'][:16]]
            print('Running original example stage:', stage, flush=True)
            with (run_root/f'{stage}.log').open('w', encoding='utf-8') as log:
                subprocess.run(command, cwd=workspace, check=True, stdout=log, stderr=subprocess.STDOUT)
        verify_outputs(output, manifest['samples'])
        with GraphDatabase.driver(graph['uri'], auth=auth) as driver:
            after = read_fixture_snapshot(driver, graph.get('database', 'neo4j'))
        if after['content_sha256'] != identity['graph_content_sha256']:
            raise ValueError('Example graph changed during inference')
        write_json(run_root/'graph_after.json', after)
        identity['status'] = 'complete'
    except Exception as error:
        identity.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        identity['ended_at'] = datetime.now(timezone.utc).isoformat()
        write_json(run_root/'run_identity.json', identity)
    print('Complete example outputs:', output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
