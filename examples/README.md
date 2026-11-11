# Run a small example

`samples/` contains two original MIT teaching pairs (four logical samples), not excerpts from the 280-sample paper benchmark. One pair illustrates a missing destination-capacity check; the other illustrates a repeated heap release. The snippets are syntax-checkable C++ functions, not a full industrial application.

## Prepare resources

Install the root dependencies, provide local Qwen3-8B and BGE-M3 weights, and start the [dedicated teaching graph](../graph/README.md). In the project root:

```bash
cp examples/config.example.yaml examples/config.yaml
```

Edit the model/embedding paths. The default graph address is `bolt://127.0.0.1:7689`, separate from a typical research database. The configuration is ignored by Git. It contains only example deployment settings; original prompts, generation budgets and decision policies remain in the selected inference scripts.

## Check inputs and import the graph

```bash
python scripts/build_dataset_manifest.py --dataset examples/samples --output outputs/example-input.json
python scripts/load_example_graph.py --config examples/config.yaml
```

The sample loader should find four inputs. The graph import must be performed only against the dedicated example database. The tool compares its live contents to `graph/example.json`; the launcher checks the same identity before inference and verifies it remains unchanged afterwards. The root `verify_sources.py` checks the selected inference sources; the example manifest additionally identifies the teaching files.

## Execute the original pipeline

Choose an idle numeric GPU index:

```bash
CUDA_VISIBLE_DEVICES=0 python scripts/run_example.py \
  --config examples/config.yaml --run-name demo
```

The helper creates a private source workspace under `outputs/demo/workspace/`, copies the verified original inference files, generates local stage configs there, then runs the existing root runner for `all` and `refine`. It does not overwrite project-level KG/Agent deployment configs. An existing run name is rejected; use a new name for an independent run.

The selected code includes a minimal tokenizer compatibility guard: an existing Transformers `all_special_tokens_extended` implementation is preserved. This prevents the legacy fallback patch from replacing a working native property. It changes startup compatibility, not model prompts or detection policy; provenance and regression tests record the change.

`--prepare-only` prepares this private workspace without opening the model or graph. Actual inference hashes model/embedding contents and may take time before model startup. Keep `outputs/` private: generated stage configs may contain the local graph password.

Outputs:

```text
outputs/demo/
├── dataset_manifest.json
├── run_identity.json
├── all.log
├── refine.log
└── workspace/outputs/example/
    ├── kg/
    ├── agent/
    ├── hybrid/
    └── hybrid_cwe_refined/
```

Fusion and refinement produce their original evaluation reports. `run_identity.json` stores content identities and redacted deployment fields, not the graph password or private model path. Complete execution requires all four samples at every stage and the frozen Global binary verdict through fusion/refinement.

## Interpretation

This is an installation and flow example, not an accuracy benchmark. It cannot establish the paper metrics, and model outputs can vary. The original loader/Agent interfaces retain identity/source fields, as documented in the main execution notes. Reference predictions must be compared together with their recorded environment and graph fixture identity.

The original no-KG ablation refinement runner requires 280 records. For four teaching inputs, use its detection stage only; this helper instead demonstrates the complete primary KG/Agent/fusion/refinement flow.

On a shared server, select unused distributed-initialization ports if the runtime reports `EADDRINUSE`; for example set `VLLM_PORT` and `MASTER_PORT` to available numeric ports. These do not select the GPU. Preserve failure logs and use a new run name for an independent retry.
