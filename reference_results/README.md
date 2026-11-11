# Reference outputs

This directory contains [actual example-run artifacts](example/README.md), with the exact input,
source, configuration, model-resource and graph identities recorded alongside them.
It does not contain the historical 280-sample paper predictions.

The public teaching inputs in `examples/samples/` and `graph/example.cypher` are
original fixtures, not the paper benchmark or OGVKG. A successful small run proves
that the stated environment executed the workflow; its metrics are not evidence
of general detection performance and are not guaranteed to repeat exactly.

After a completed real run, export a reviewable bundle:

```bash
python scripts/export_example_reference.py \
  --run-dir outputs/demo --config examples/config.yaml \
  --output reference_results/example
```

The exporter requires complete KG/Agent/fused/refined records and the frozen Global
binary verdict. It copies only predictions, the original evaluator reports,
redacted stage configs, dataset/model/source identities and an observed snapshot
of the dedicated teaching graph. It never copies private workspace configs or
runtime logs. The graph observation is taken at export time and compared with
the expected fixture and the recorded run identity. Older launches without a
pre-run live snapshot require an explicit `--allow-post-run-graph-check` flag;
the export records that limitation rather than inventing an earlier observation.

The original KG script does not persist every raw model completion or finish
reason. Accordingly, the bundle is not advertised as a full per-token call trace.
Agent/refinement evidence fields are preserved as emitted by the original tools.
