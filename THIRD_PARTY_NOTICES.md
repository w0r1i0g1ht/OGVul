# Licensing and third-party resources

The root [MIT license](LICENSE) applies to original OGVul detection code, project tools and documentation, and the original teaching examples. It does **not** relicense third-party source, datasets, model weights or knowledge resources.

| Material | Location / handling | License boundary |
|---|---|---|
| Original detection code, tools and docs | Root Python files, `kg/`, `agent/`, `ablations/`, `scripts/`, project Markdown | MIT for the authors' original contributions; third-party dependencies retain their own licenses. |
| Original public teaching code | `examples/samples/` | MIT. Authored for this repository, not copied from the paper benchmark or industrial projects. |
| Original tiny teaching graph | `graph/example.cypher`, `graph/example.json` | MIT. Independently authored fixture; not the paper OGVKG. CWE identifiers are references to the external CWE taxonomy. |
| GPL-derived paper samples | Reserved `data/third_party_samples/` area; none included in this package | Original project copyright, source provenance, modification notices and corresponding GPL terms must be retained per sample. The root MIT license does not apply to these third-party portions. |
| CWE hierarchy CSV | `1000.csv`, `ablations/without_kg/1000.csv` | Third-party MITRE CWE material, not MIT-licensed by OGVul. The original copied files are unmodified. |
| Full graph and source documents | Not included | Domain/vendor documents, extracted triples and public security resources need individual provenance and permission checks. |
| Models and software dependencies | Installed externally | Qwen3, BGE-M3, Neo4j, vLLM, PyTorch and Transformers retain their own upstream licenses. No model weights or database distribution is included here. |

## CWE

CWE is maintained by The MITRE Corporation. The official terms grant non-exclusive, royalty-free use for research, development and commercial purposes, conditioned on reproducing MITRE's copyright designation and license in copies. A local copy of the copyright notice, license grant and disclaimers is retained in [LICENSES/CWE-Terms.txt](LICENSES/CWE-Terms.txt). Refer also to the [official terms](https://cwe.mitre.org/about/termsofuse.html) and [Research Concepts view](https://cwe.mitre.org/data/definitions/1000.html). Preserve this notice when distributing the CSVs; they are not an OGVul MIT dataset.

The two copied CSVs have SHA-256 `2f8f0b969938be8af81bb7cf9a5d8e056bb80f0730226531efb85ea313bbaf22`. The exact upstream export version was not recorded in the original local material and is not inferred from the filename. The official terms were checked for this delivery; attribution does not establish the historical export version.

## GPL paper samples

Original benchmark fragments derive from projects including OpenFOAM, OPM and ResInsight. Merely mutating a fragment does not remove the upstream license. Before adding any fragment under `data/third_party_samples/`, retain its project/version/file/function provenance, original copyright notices, the applicable GPL text and a description of modifications. Do not mix it into `examples/samples/` or label it MIT. See [data availability](data/README.md).

No GPL paper code, vendor PDF/HTML archive, graph dump, LLM extraction checkpoint or proprietary source document is included by this delivery. Dataset hashes and annotations identify the local inventory; they do not grant rights to redistribute its source files.

## Reference outputs

`reference_results/` contains observations produced by the stated software/models on the named teaching inputs. They are not model weights or a new license grant for upstream resources. They demonstrate an execution, not the paper benchmark performance or a guarantee of identical stochastic outputs.
