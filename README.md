# OGVul

OGVul combines domain knowledge retrieval and multi-agent source-code analysis for vulnerability detection in oil-and-gas software.

本目录从原始研究代码中选择 KG-RAG、Agent、融合、CWE 精炼和评估所需文件。保留原文件名、模块关系和检测逻辑；文件来源见 [代码来源](docs/SOURCE_SELECTION.md)。当前尚不能确认这份代码精确对应论文最终指标的生成版本，不承诺一次运行得到相同分数。

## 目录与流程

```text
kg/                       KG-RAG：抽取、检索和二分类
agent/                    Agent：规划、源码核验和 CWE 判断
run_historical_hybrid.py        分阶段运行入口
hybrid_fuse_results.py          沿用 KG 二分类，优先采用 Agent CWE
hybrid_cwe_refine_offline.py     CWE 精炼，保持二分类不变
evaluate.py                    结果评估
1000.csv                       CWE 层级数据
tests/                         原入口的 CPU 检查
ablations/                     消融配置与独立无 KG 实现
docs/                          数据、配置和来源说明
examples/                      原创教学样例与独立运行配置
data/                          完整数据的清单与获取说明
graph/                         教学图谱与研究图谱准备说明
reference_results/             实际示例输出及生成条件
```

## 安装

推理使用 Linux、Python 3.10、CUDA 12.4 和原生离线 vLLM。模型直接从本地权重加载。

```bash
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cu124
python -m pip install -r requirements.txt
```

依赖文件按此前可运行的环境整理，并非论文实验当时的完整环境锁文件。模型、数据集及 Neo4j 图谱需自行准备，不包含在本目录中。

## 配置

在项目根目录执行：

```bash
cp kg/config.example.yaml kg/config.yaml
cp agent/config.example.yaml agent/config.yaml
```

编辑两份 `config.yaml` 中的模型目录、BGE-M3 目录和 Neo4j 连接信息。它们是本地配置，已被 Git 忽略。示例中的 `/path/to/...` 和 `CHANGE_ME` 必须替换；普通 YAML 不会自动展开环境变量。使用下面的入口时，数据和输出目录由命令行参数统一设置。

## 运行

先验证代码文件未被意外改动：

```bash
python verify_sources.py
```

然后运行 KG、Agent 和融合：

```bash
CUDA_VISIBLE_DEVICES=0 python run_historical_hybrid.py \
  --stage all \
  --dataset-dir /datasets/ogvul \
  --experiment-name run-001 \
  --graph-version my-neo4j-snapshot
```

**原入口的 `all` 仅包含 KG、Agent 和融合。CWE 精炼需要另行执行：**

```bash
CUDA_VISIBLE_DEVICES=0 python run_historical_hybrid.py \
  --stage refine \
  --dataset-dir /datasets/ogvul \
  --experiment-name run-001 \
  --graph-version my-neo4j-snapshot
```

阶段还可选 `kg`、`agent`、`fuse`。继续同一实验时保持数据、配置、实验名和图谱标签一致；改变条件时使用新实验名。`--graph-version` 是人工记录的标签，不能代替图谱内容校验。数值 GPU 编号和显存比例应按实际设备设置。

结果位于 `outputs/run-001/`，包括生成配置、数据清单、KG/Agent/融合输出，以及 `hybrid_cwe_refined/` 精炼输出。输出中的生成配置可能包含本地密码，不应提交。

## 评估

融合和精炼脚本会调用原评估器，也可单独运行：

```bash
python evaluate.py --input outputs/run-001/hybrid_cwe_refined/detection_results_hybrid_cwe_refined.json
```

数据格式、图谱要求及原实现的行为说明见 [数据与运行条件](docs/DATA_AND_EXECUTION.md)。

## 小示例与资源

- [小示例运行说明](examples/README.md)：两组原创 MIT 教学样例，四条逻辑输入；使用独立小图谱运行主流程。
- [完整数据说明和清单](data/README.md)：280条本地库存的哈希、实际读取顺序和已发现的标注兼容性问题。数据源码不随本包分发。
- [图谱准备](graph/README.md)：可直接导入的教学图谱、实际查询所需schema，以及完整研究图谱尚未解决的版本/分发边界。
- [参考输出](reference_results/README.md)：以实际运行和生成条件为准，不把教学运行称为论文指标复现。

不要把教学样例或小型教学图谱替换进论文基准后报告为OGVKG实验结果。

## 消融实验

已包含论文涉及的三项消融选项，具体配置和命令见 [消融运行说明](docs/ABLATIONS.md)。

| 选项 | 执行方式 |
|---|---|
| Base-LLM | 原 KG 脚本的 `base_llm` 模式，不执行图谱或 embedding 加载 |
| w/o Agent | 原 KG 脚本的 `kg_rag` 模式，不执行 Agent、融合或精炼 |
| w/o KG | 独立 `ablations/without_kg/` 工程，不连接 Neo4j 或加载 BGE |

每项使用独立的配置、输出和检查点。现存消融代码与论文历史分数的精确版本绑定尚未确认；尤其独立 w/o KG 工程来自统一 Agent 流程，不能直接认定为当前 Hybrid 主流程仅删除 KG 后的严格对照。

## 轻量检查

```bash
python -B -m unittest discover -s tests -v
```

这些检查不加载大模型，不能证明 GPU 推理兼容或重新生成的论文指标。

## 许可与引用

原创检测代码、工具、文档和教学样例采用 [MIT](LICENSE)。GPL来源论文样本、CWE等第三方资源及模型分别遵守原许可，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。根MIT不覆盖整个数据与资源集合。

引用信息见 [CITATION.cff](CITATION.cff)。论文题目和作者按手稿核对；尚未核实的DOI、页码和仓库发布地址没有填写。
