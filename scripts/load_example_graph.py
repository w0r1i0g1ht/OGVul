# SPDX-License-Identifier: MIT
"""Import only the original teaching fixture into a dedicated example database."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def canonical_snapshot(body):
    key = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True)
    result = dict(nodes=sorted(body['nodes'], key=key), relationships=sorted(body['relationships'], key=key))
    result['content_sha256'] = hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False,
        separators=(',', ':')).encode('utf-8')).hexdigest()
    return result


def expected_fixture_snapshot():
    return canonical_snapshot(json.loads((ROOT/'graph/example.json').read_text(encoding='utf-8')))


def assert_fixture_snapshot(snapshot):
    if snapshot['content_sha256'] != expected_fixture_snapshot()['content_sha256']:
        raise ValueError('Example graph contents differ from the expected fixture')


def graph_connection(config):
    graph = config['graph']
    variable = graph.get('password_env')
    if variable and not os.environ.get(variable):
        raise ValueError(f'Missing graph password environment variable: {variable}')
    auth = (graph.get('username', 'neo4j'), os.environ[variable]) if variable else None
    return graph, auth


def import_fixture(driver, database, fixture):
    with driver.session(database=database) as session:
        count = session.run('MATCH (n) WHERE NOT n:OGVulExample RETURN count(n) AS count').single()['count']
        if count:
            raise ValueError('Refusing to import: database contains non-example nodes')
        session.run(fixture).consume()
        nodes = session.run('MATCH (n) RETURN count(n) AS count').single()['count']
        relationships = session.run('MATCH ()-[r]->() RETURN count(r) AS count').single()['count']
    return dict(nodes=nodes, relationships=relationships)


def read_fixture_snapshot(driver, database):
    """Record portable graph contents, without Neo4j-internal element IDs."""
    with driver.session(database=database) as session:
        foreign = session.run('MATCH (n) WHERE NOT n:OGVulExample RETURN count(n) AS count').single()['count']
        if foreign:
            raise ValueError('Refusing to export a graph with non-example nodes')
        nodes = [dict(labels=sorted(row['labels']), properties=dict(row['properties'])) for row in
                 session.run('MATCH (n) RETURN labels(n) AS labels, properties(n) AS properties')]
        relationships = [dict(source=dict(labels=sorted(row['source_labels']), properties=dict(row['source_properties'])),
            type=row['type'], properties=dict(row['properties']),
            target=dict(labels=sorted(row['target_labels']), properties=dict(row['target_properties']))) for row in session.run(
            'MATCH (a)-[r]->(b) RETURN labels(a) AS source_labels, properties(a) AS source_properties, '
            'type(r) AS type, properties(r) AS properties, labels(b) AS target_labels, properties(b) AS target_properties')]
    if not nodes:
        raise ValueError('Example graph is empty; import graph/example.cypher first')
    return canonical_snapshot(dict(nodes=nodes, relationships=relationships))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT/'examples/config.yaml')
    args = parser.parse_args(argv)
    config = yaml.safe_load(args.config.read_text(encoding='utf-8'))
    graph, auth = graph_connection(config)
    from neo4j import GraphDatabase
    fixture = ROOT/'graph/example.cypher'
    with GraphDatabase.driver(graph['uri'], auth=auth) as driver:
        driver.verify_connectivity()
        counts = import_fixture(driver, graph.get('database', 'neo4j'), fixture.read_text(encoding='utf-8'))
        snapshot = read_fixture_snapshot(driver, graph.get('database', 'neo4j'))
        assert_fixture_snapshot(snapshot)
    print(json.dumps(dict(**counts, content_sha256=snapshot['content_sha256'],
                         fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
