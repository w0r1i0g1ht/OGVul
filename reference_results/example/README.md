# Recorded teaching run

This bundle was generated on a server using the four original MIT inputs in
`examples/samples/` and the original teaching graph in `graph/`. It is not a
reproduction of the paper's 280-sample benchmark or its full OGVKG.

The existing server environment executed KG, Agent, fusion and CWE refinement
using native offline vLLM, Qwen3-8B and BGE-M3. This verifies execution in that
environment; installation from scratch was not tested. Runtime versions,
effective redacted configurations, source hashes and local model-resource hashes
are in [run_identity.json](run_identity.json), [kg.redacted.yaml](kg.redacted.yaml)
and [agent.redacted.yaml](agent.redacted.yaml).

Observed hardware was one NVIDIA L20 (44.42 GiB reported by vLLM), driver
560.35.03, tensor parallel size 1, GPU memory utilization 0.7. The run used
`VLLM_USE_V1=0`, loopback distributed networking and explicit available ports.
The dedicated loopback graph used Neo4j 2026.01.4 and Java 21.0.10.

| Final refined metric | Observed value |
|---|---:|
| Logical inputs | 4 (2 vulnerable, 2 safe) |
| TP / FP / FN / TN | 2 / 0 / 0 / 2 |
| Accuracy / Precision / Recall / F1 | 100% each |
| Strict CWE hit rate on vulnerable inputs | 2/2 |

See the unmodified original evaluator's [JSON](evaluation.json) and
[Markdown](evaluation.md) reports. Re-evaluation with the repository evaluator
matches all report contents except the newly generated evaluation timestamp.
All stages contain four `success` records and fusion/refinement preserve the
KG Global binary verdict. These tiny teaching results do not estimate general
detection performance, and stochastic generation may differ on another run.

## Execution limitations

The original Agent reported final-fusion JSON parsing failures for
`Sample_DemoRelease_vuln`, `Sample_DemoBuffer_safe` and
`Sample_DemoRelease_safe`, and used its existing conservative fallback. The
emitted `success` status therefore does not mean every internal model response
parsed successfully. Outputs are retained as produced; no sampling or decision
rules were changed to improve these scores. The selected code contains the
documented tokenizer compatibility guard; see [source selection](../../docs/SOURCE_SELECTION.md).

This completed attempt followed two startup failures: tokenizer compatibility,
then a distributed-port collision. Failed-run logs remain outside this public
bundle. This completed attempt was not selected from multiple completed scored
runs.

The graph contains 16 nodes and 34 relationships. Its observed canonical content
SHA-256 is `a4923e141f1e2d99e5ddd20804eeac0fdcf0504b8f7b836ce3f458140f1f7fa7`.
It was imported before inference and checked during execution and at export.
This older launcher recorded the fixture file identity at startup but did not
save a pre-run live graph snapshot. Export explicitly acknowledged this gap;
[artifact_manifest.json](artifact_manifest.json) records it. The current launcher
adds pre/post-run live graph checks. An export snapshot cannot prove the graph
was unchanged throughout inference.

The original KG script does not persist every raw completion or finish reason.
These files are reference observations, not a complete token-level audit trail.
The dedicated temporary graph was stopped after export and the example GPU
processes exited. Model weights, private configurations and runtime logs are
not distributed here.

[artifact_manifest.json](artifact_manifest.json) supplies SHA-256 hashes for the
generated artifacts (excluding this explanatory README). Resource licenses and
the scope of MIT are described in [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).
