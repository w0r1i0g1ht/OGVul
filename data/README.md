# Dataset integrity metadata

`paper_manifest.json` is integrity metadata for the existing local 280-sample
dataset. It preserves the original `kg/data_loader.py` discovery, order, labels,
and source types. The manifest contains hashes and metadata only; it contains
no source code.

This local dataset is not directly readable by the checked-in loader and current
`SampleInfo` schema: four CVE annotations use list-valued `cwe_id` fields, while
the schema requires a string. The checked-in paper inventory was generated only
with the explicit `--normalize-cwe-lists` inventory mode. That mode does not
modify source data or make it runtime-compatible: it keeps every original
multi-CWE list in `annotation_normalization.affected_samples`, selects no CWE
from a multi-value list, and marks `loader_compatible` as `false`.

It is not evidence that this local dataset, a particular graph snapshot, model,
or runtime configuration produced the historical paper results.

The dataset and annotations will be made available upon reasonable request.
Please contact zhang_peng@njust.edu.cn or sunbo@chanct.com. No download URL is
claimed here.

## Expected layout and ordering

At the dataset root, CVE samples use `CVE-*/vuln_code.md` and optional
`vuln_info.json`. Synthetic pairs use `Sample_*/mutated_code.cpp`,
`Sample_*/safe_code.cpp`, and optional `vuln_info.json`. Logical samples load
in this order: vulnerable CVEs, fixed CVEs, synthetic vulnerable samples, then
synthetic safe samples; each group is directory-name sorted.

Generate a new manifest (outside the dataset directory):

```bash
python -B scripts/build_dataset_manifest.py --dataset /datasets/ogvul --output data/manifest.json
```

Verify an existing manifest:

```bash
python -B scripts/build_dataset_manifest.py --dataset /datasets/ogvul --verify data/paper_manifest.json
```

For this repository's historical 280-sample inventory, explicitly acknowledge
the annotation incompatibility:

```bash
python -B scripts/build_dataset_manifest.py --dataset /datasets/ogvul --output data/paper_manifest.json --normalize-cwe-lists
python -B scripts/build_dataset_manifest.py --dataset /datasets/ogvul --verify data/paper_manifest.json --normalize-cwe-lists
```

`examples/samples` contains original MIT-licensed teaching samples only. They
are not paper samples. GPL-derived paper sample source code is not included in
this repository; see `third_party_samples/README.md`.
