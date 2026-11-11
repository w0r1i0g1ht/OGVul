# SPDX-License-Identifier: MIT
"""Export only verified teaching outputs and redacted provenance, never private configs."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_example import sha, verify_outputs, write_json
from scripts.load_example_graph import graph_connection, read_fixture_snapshot, assert_fixture_snapshot


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=ROOT/'examples/config.yaml')
    parser.add_argument('--output', type=Path, default=ROOT/'reference_results/example')
    parser.add_argument('--allow-post-run-graph-check', action='store_true',
                        help='Explicitly export an older run without a pre-run live graph snapshot; record this limitation')
    args = parser.parse_args(argv)
    run = args.run_dir.resolve()
    identity = json.loads((run/'run_identity.json').read_text(encoding='utf-8'))
    if identity['status'] != 'complete':
        raise ValueError('Export requires a completed real example run')
    dataset = json.loads((run/'dataset_manifest.json').read_text(encoding='utf-8'))
    results = run/'workspace/outputs/example'
    verify_outputs(results, dataset['samples'])
    if args.output.exists():
        raise FileExistsError('Reference output already exists; choose another directory')
    config = yaml.safe_load(args.config.read_text(encoding='utf-8'))
    graph, auth = graph_connection(config)
    from neo4j import GraphDatabase
    with GraphDatabase.driver(graph['uri'], auth=auth) as driver:
        snapshot = read_fixture_snapshot(driver, graph.get('database', 'neo4j'))
    assert_fixture_snapshot(snapshot)
    recorded_graph = identity.get('graph_content_sha256')
    if recorded_graph and recorded_graph != snapshot['content_sha256']:
        raise ValueError('Graph differs from the graph recorded for inference')
    if not recorded_graph and not args.allow_post_run_graph_check:
        raise ValueError('Run has no pre-run live graph identity; require explicit post-run-only acknowledgement')
    args.output.mkdir(parents=True)
    files = {}
    for stage, original, name in (
        ('kg', 'detection_results_kg_rag.json', 'kg.json'),
        ('agent', 'detection_results_agent_kg_rag.json', 'agent.json'),
        ('hybrid', 'detection_results_hybrid_kg_agent.json', 'fused.json'),
        ('hybrid_cwe_refined', 'detection_results_hybrid_cwe_refined.json', 'refined.json')):
        source = results/stage/original
        shutil.copyfile(source, args.output/name)
        files[name] = sha(source)
    reports = sorted((results/'hybrid_cwe_refined').glob('evaluation_report_*.json'))
    if len(reports) != 1:
        raise ValueError('Expected one original refined evaluation report')
    for source, name in [(reports[0], 'evaluation.json'), (reports[0].with_suffix('.md'), 'evaluation.md')]:
        shutil.copyfile(source, args.output/name); files[name] = sha(source)
    for branch in ('kg', 'agent'):
        settings = yaml.safe_load((run/'workspace'/branch/'config.yaml').read_text(encoding='utf-8'))
        for phase in ('extraction', 'diagnosis'):
            settings['llm'][phase]['model_path'] = '${MODEL_DIR}'
        settings['llm']['embedding']['model_path'] = '${EMBEDDING_DIR}'
        settings['neo4j'].update(uri='${DEDICATED_EXAMPLE_GRAPH_URI}', username='${GRAPH_USERNAME}',
            password='${GRAPH_PASSWORD}' if settings['neo4j']['password'] else '')
        settings['paths'] = dict(cve_dir='${EXAMPLE_SAMPLES}', synthetic_dir='${EXAMPLE_SAMPLES}',
                                 output_dir='${RUN_OUTPUT}/'+branch)
        path = args.output/(branch+'.redacted.yaml')
        path.write_text(yaml.safe_dump(settings, sort_keys=False), encoding='utf-8'); files[path.name] = sha(path)
    write_json(args.output/'dataset_manifest.json', dataset)
    write_json(args.output/'run_identity.json', identity)
    write_json(args.output/'graph_snapshot.json', snapshot)
    files.update({name:sha(args.output/name) for name in ['dataset_manifest.json','run_identity.json','graph_snapshot.json']})
    write_json(args.output/'artifact_manifest.json', dict(purpose='Real teaching example outputs, not paper results',
        graph_observation='Recorded after the completed run from the dedicated example database', files=files))
    metadata = json.loads((args.output/'artifact_manifest.json').read_text(encoding='utf-8'))
    metadata['graph_binding'] = 'pre/post-run live content identity plus export check' if recorded_graph else (
        'Fixture file identity recorded at startup; actual graph checked against expected fixture at export. '
        'No pre-run live content snapshot was recorded by this older launcher.')
    write_json(args.output/'artifact_manifest.json', metadata)
    print(args.output)


if __name__ == '__main__':
    main()
