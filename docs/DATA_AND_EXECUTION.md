# 数据与运行条件

## 数据目录

入口要求 CVE 和合成样本放在同一根目录，并通过 `--dataset-dir` 指定：

```text
/datasets/ogvul/
├── CVE-YYYY-NNNN/
│   ├── vuln_code.md
│   └── vuln_info.json
├── CVE-YYYY-NNNN-fixed/
│   ├── vuln_code.md
│   └── vuln_info.json
└── Sample_CWEXXX_NNN/
    ├── mutated_code.cpp
    ├── safe_code.cpp
    └── vuln_info.json
```

`vuln_code.md` 的源码位于 fenced code block 中。一个 `Sample_*` 目录的两份源码分别算作漏洞样本和安全样本。原加载器按 CVE 漏洞、CVE 修复、合成漏洞、合成安全四段加载，每段按目录排序。标注读取规则保留在两支的 `data_loader.py` 中。入口会检查实际可加载数量；论文中的数据组成是55个CVE漏洞、25个CVE修复、100组合成漏洞/安全对，共280条逻辑样本。

完整本地数据的最新库存检查发现4条CVE使用多值 `cwe_id` 列表，当前原加载器的字符串schema不能直接读取。详见 [数据清单说明](../data/README.md)。清单中的显式库存规范化不修改原数据，也不代表已经选择了评估用的唯一CWE；完整实验前需先确认标注语义。公开教学样例使用兼容的单CWE格式。

## 模型和图谱

两份配置分别指定 Qwen3-8B、BGE-M3 和 Neo4j。模型目录需包含可读取的模型权重、配置和 tokenizer 文件。完整实验需要与原检索规则兼容的图谱；本目录未分发完整OGVKG构建输入或论文数据库快照，仅提供原创教学图谱及其导入工具。

[graph/](../graph/README.md) 提供可独立导入的原创教学fixture及完整研究图谱的准备边界；教学图谱不等于OGVKG。

原查询依赖 `OGL_Node`、`Entity`、`Domain`、`CWE`、`PotentialWeakness` 等标签及 `BELONGS_TO`、`INDUSTRIAL_LOGIC`、`POTENTIAL_WEAKNESS`、`CHILD_OF` 等关系。完整查询以两支 `main_offline.py` 为准。相同代码连接不同图谱可能产生不同结果；不要把人工图谱版本名当作实际快照身份。

## 保留的原始行为

原检测脚本逐字复制，保留原提示词、批处理、thinking、解析兜底、二次核验和精炼政策。配置中的部分生成设置并非所有阶段都会读取，实际采样参数以原脚本为准；单改 YAML 的温度不保证改变每个阶段。

原 Agent 规划提示会接收 `sample_id` 和 `source_type`，精炼提示也包含样本身份；原数据命名和来源类别可能带有 CWE、safe、vuln、fixed 等标签线索。这里保留原接口，便于核查研究实现，不宣称已经消除了此类线索。新的严格评估需单独处理并记录这项行为变化。

原流程会复用已有成功记录或精炼检查点。进行独立重复实验时使用新实验名，避免把已有缓存当作新的模型推理。运行波动、图谱差异和未确认的历史版本可能使结果不同于论文历史记录。

## 阶段与输出

| 阶段 | 主要文件 |
|---|---|
| KG | `kg/detection_results_kg_rag.json` |
| Agent | `agent/detection_results_agent_kg_rag.json` |
| 融合 | `hybrid/detection_results_hybrid_kg_agent.json` |
| CWE精炼 | `hybrid_cwe_refined/detection_results_hybrid_cwe_refined.json` |

以上路径相对于 `outputs/<experiment-name>/`。精炼不会改变融合结果的二分类判定。评估应使用完整样本集合，错误、缺失记录不能静默剔除后声称完整实验完成。
