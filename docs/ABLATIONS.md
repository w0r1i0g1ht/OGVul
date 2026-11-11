# 消融实验

当前目录包含论文中的 Base-LLM、w/o KG 和 w/o Agent 三项执行选项，保留选定原始脚本的检测逻辑。此处说明代码和运行入口，不声明已经重新得到论文消融指标。

## Base-LLM

复用 `kg/main_offline.py` 的原始 `base_llm` 分支。该分支不执行图谱检索、embedding 加载、Agent、融合或 CWE 精炼；仍采用原脚本的二分类、CWE 定位和报告阶段，不是新写的单次提示实现。

从项目根目录准备独立配置：

```bash
cp ablations/base_llm.example.yaml kg/config.base_llm.yaml
```

编辑模型和数据的绝对路径。配置没有 `neo4j` 或 `llm.embedding` 字段，但原模块顶层仍导入 Neo4j 库，因此安装环境沿用根目录依赖文件。输出默认相对项目根目录：`outputs/ablations/base_llm/run-001`。若修改输出目录，同步修改以下命令：

```bash
mkdir -p outputs/ablations/base_llm/run-001
CUDA_VISIBLE_DEVICES=0 python kg/main_offline.py --config config.base_llm.yaml
python evaluate.py --input outputs/ablations/base_llm/run-001/detection_results_base_llm.json
```

`--config` 的相对路径由原脚本按 `kg/` 解析；上面的配置参数不要再加一层 `kg/`。运行时保持工作目录为项目根目录。

## w/o Agent

复用相同脚本的 `kg_rag` 分支，只运行单分支 KG-RAG，不接着执行 Agent、Hybrid 融合或精炼。无需再复制一套 KG 实现：

```bash
cp ablations/without_agent.example.yaml kg/config.without_agent.yaml
```

编辑模型、BGE-M3、数据和 Neo4j 连接信息，在项目根目录执行：

```bash
mkdir -p outputs/ablations/without_agent/run-001
CUDA_VISIBLE_DEVICES=0 python kg/main_offline.py --config config.without_agent.yaml
python evaluate.py --input outputs/ablations/without_agent/run-001/detection_results_kg_rag.json
```

这里使用的是当前选定的原 KG 实现。历史实验汇总将论文参考 F1=55.17% 指向更早的实验结果；这不能证明当前脚本就是生成该分数的版本。运行结果应独立报告，不能直接标成论文原结果。

## w/o KG

独立代码位于 `ablations/without_kg/`，来自原始 `scripts/agent_vuln_detect_without_kg/`。保留 Global 感知、Orchestrator、Verifier、Defense、Final Judge、全局检查点及 CWE 精炼。

当前有效入口不连接 Neo4j、不加载 BGE、不读取 KG 检测结果；预警和图谱证据字段为空。`offline_runtime.py` 中还保留历史 KG 辅助函数及禁用的旧独立主流程，但有效 Agent 入口不调用这些路径。本轮没有从这些原文件中重新抽取或改写推理逻辑。

切换到该目录后准备配置：

```bash
cd ablations/without_kg
cp config.example.yaml config.yaml
```

将模型、数据和 `paths.output_dir` 都填写为绝对路径。例如将输出设为 `/runs/ogvul/without_kg/run-001`。原 runner 会为子进程切换工作目录，绝对路径可避免检查点与结果定位不一致。配置没有 Neo4j 或 embedding 项。

```bash
CUDA_VISIBLE_DEVICES=0 python run_pipeline.py --stage detect
CUDA_VISIBLE_DEVICES=0 python run_pipeline.py --stage refine
```

也可使用 `--stage all` 连续执行检测和精炼。**这个 runner 的 `all` 包含精炼，与根目录 Hybrid runner 的 `all` 定义不同。** 原无 KG runner 在精炼前固定检查280条成功记录，其他规模的数据不适合直接使用这条精炼入口。

输出为：

```text
<paths.output_dir>/
├── detection_results_unified_agent_without_kg.json
├── global_perception_checkpoint_without_kg.json
└── cwe_refined/
    └── detection_results_unified_cwe_refined.json
```

返回项目根目录，用相同评估器评估选定阶段：

```bash
cd ../..
python evaluate.py --input /runs/ogvul/without_kg/run-001/detection_results_unified_agent_without_kg.json
python evaluate.py --input /runs/ogvul/without_kg/run-001/cwe_refined/detection_results_unified_cwe_refined.json
```

现存原 w/o KG 工程基于统一/global-local Agent 流程，其 binary 由 Global 判断及 Defense gate 等原政策共同约束，并非自由多智能体投票；它与选定的 Hybrid 主流程不保证只相差 KG 这一项。其版本与论文 F1=61.65%、HPS=44.65% 的精确绑定仍未确认。

## 配置、重复运行与比较

- 所有示例都保留原模型预算和采样字段，仅通过模式选择实验，并替换部署路径或密码。原脚本存在硬编码采样设置，实际生效值以代码为准。
- 使用同一数据集合、标注、模型和评估器。图谱消融还应固定图谱快照；人工版本标签不足以证明图内容一致。
- Base-LLM 和 w/o Agent 默认使用各自的 `run-001` 输出目录；新实验应同时更换配置输出目录和命令中的路径。
- w/o KG 在同一输出目录会复用原成功记录和全局/CWE检查点。独立重复运行必须使用新输出目录，不能把缓存命中算作一次重新推理。
- 三项均未在本次整理中重新执行 GPU 推理。CPU 检查验证源码、配置和执行边界，不证明历史指标可重新生成。
