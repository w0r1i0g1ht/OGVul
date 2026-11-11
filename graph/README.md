# Graph preparation

There are two different resources: the original OGVKG used for research and the small original teaching fixture shipped here. They are not interchangeable for reporting benchmark performance.

## Run the teaching fixture

Use a dedicated empty Neo4j database. The original queries use the `CALL (name) { ... }` scope syntax; the reference environment uses Neo4j 2026.01.4 with Java 21. A loopback-only disposable Docker example is:

```bash
docker run --rm -d --name ogvul-example-graph \
  -p 127.0.0.1:7689:7687 -p 127.0.0.1:7476:7474 \
  -e NEO4J_AUTH=none neo4j:2026.01.4-community
```

Wait for Neo4j to report `Started`, copy `examples/config.example.yaml` to `examples/config.yaml`, then import:

```bash
python scripts/load_example_graph.py --config examples/config.yaml
```

The tool refuses to write when the target database contains any node without the `OGVulExample` label. It uses `MERGE` and does not delete nodes. Do not relabel an existing research graph to bypass this check. If the dedicated database uses authentication, put the environment-variable name in `graph.password_env` and export the password locally.

`example.cypher` is original MIT teaching material. It creates 11 entity nodes, two domains and three CWE reference nodes, including namespace membership and weakness links. `example.json` records the expected portable node/relationship contents. The importer and launcher check the live content hash, not merely labels or counts; the launcher also compares pre/post-run identities. It exercises the same schema as the original queries but does not reproduce the content or coverage of OGVKG.

After the example run, stop the container:

```bash
docker stop ogvul-example-graph
```

The disposable graph has no persistent volume in this command. The inference outputs remain in the project output directory.

## Required schema

| Item | Required representation |
|---|---|
| Retrieval candidates | `OGL_Node.name` |
| Domain filtering | `(e:Entity)-[:BELONGS_TO]->(d:Domain)` with `name` fields |
| Weakness cues | `(n:OGL_Node)-[:INDUSTRIAL_LOGIC*0..1]->(v:OGL_Node)-[r:POTENTIAL_WEAKNESS]->(c)` |
| Weakness identifiers | `c:CWE` or `c:PotentialWeakness`, `id` or `cwe_id` |
| Context | `r.reason`, `c.name`, `c.verification_contract` or `c.mitigations` |
| CWE ancestors | `(cwe:CWE)-[:CHILD_OF*0..2]->(parent:CWE)` |

Read-only checks after importing the fixture:

```cypher
MATCH (n) RETURN labels(n) AS labels, count(*) AS count;
MATCH (e:Entity)-[:BELONGS_TO]->(d:Domain)
RETURN e.name, d.name;
MATCH (n:OGL_Node)-[:POTENTIAL_WEAKNESS]->(c:CWE)
RETURN n.name, c.id;
```

## Full OGVKG availability and construction provenance

The full research graph is not shipped. The current local graph dump has not been proven to match the paper experiment, and the input documents/extracted outputs do not have a complete redistribution manifest. A filename, modification time or manually supplied `--graph-version` is not a content identity.

The original research materials show this construction sequence:

1. `knowledge-graph-construction/batch_extract_knowledge.py` scans domain PDF/HTML files, extracts text and invokes `src/knowledge_graph/main.py` to produce triples.
2. `import_ogknowledge/import_knowledge_from_json.py` imports extracted domain nodes and `INDUSTRIAL_LOGIC`, assigning compatible labels and weakness bridges.
3. `import_ogknowledge/import_bridge_only.py` applies additional bridge checkpoint results.
4. `import_vuln/import_cwe_full.py` imports CWE and hierarchy relations; companion scripts import advanced CWE, CSAF/CPE and CAPEC relations.

These paths identify the original materials, not runnable files included in this repository. The exact upstream versions, transformation order and domain-document permissions are not fully bound. Therefore these steps are a provenance account, not a claim that the paper graph can already be rebuilt from this package.

For a full-graph release, provide the actual inputs or a redistributable snapshot, hashes, licenses and ordered import scripts, using `resource_manifest.example.yaml` as the record format. Please contact the paper authors for graph availability. Do not substitute the tiny fixture when reporting OGVKG evaluation results.

Third-party extraction tooling and graph source documents are not relicensed by the project MIT license; see [third-party notices](../THIRD_PARTY_NOTICES.md).
