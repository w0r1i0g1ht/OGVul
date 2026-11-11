# 代码来源与选择范围

从原始研究目录 `scripts/agent_kg_vuln_detect/historical_hybrid/` 直接选择本目录文件。没有沿用此前重构版的 `src/ogvul` 实现。

## 选入文件

- `kg/`：`main_offline.py`、`schemas.py`、`data_loader.py`。
- `agent/`：`main_agent_offline.py`、它依赖的 `main_offline.py`、`schemas.py`、`agent_schemas.py`、`data_loader.py`。
- 根目录：原分阶段入口、源文件校验器、融合、精炼、评估脚本及 `1000.csv`。
- `tests/`：原入口已有的 CPU 测试。

主流程来自原始运行脚本，仅为功能化目录名调整路径引用、入口说明、默认输出路径和追踪字段；测试夹具中的个人目录已替换为匿名示例路径。未改动模型提示词、采样参数或检测决策规则。未选入HTTP API入口、重复pipeline、外部baseline、模型、数据集、缓存、历史结果与日志。

## 补入的消融

- `ablations/without_kg/` 直接复制原 `scripts/agent_vuln_detect_without_kg/` 的12个Python文件和CWE数据，包括主入口、离线工具、decision policy、全局检查点、二分类恢复、模型兼容层及精炼/评估依赖。除两处来源注释去除日期标记外，保留原代码；配置只脱敏部署路径。
- Base-LLM 和 w/o Agent 复用当前 `kg/main_offline.py`，分别提供 `ablations/base_llm.example.yaml` 和 `ablations/without_agent.example.yaml`。Base-LLM 配置删除图谱和embedding字段，执行原 `base_llm` 模式；w/o Agent执行原 `kg_rag` 模式。
- 新增 `tests/test_ablation_setup.py`，检查配置隔离、无KG有效入口的调用边界与依赖，以及用假模型执行完整原Base-LLM流程，确认不会连接图谱或加载embedding。它是本次整理的检查代码，不是历史实验代码。
- 具体命令、工作目录和版本绑定限制见 [消融运行说明](ABLATIONS.md)。这些选项不是外部baseline，也不意味着已经匹配论文历史分数。

## 整理内容

- 两份原配置转为 `config.example.yaml`，仅替换模型/数据/输出路径和数据库部署信息；密码为 `CHANGE_ME`。原采样设置和运行策略字段保留。
- 依赖文件取此前可运行环境中的必要库版本，未沿用原 requirements 中的宽松或不匹配版本范围。
- 新增使用说明、忽略规则和来源清单。
- 主流程目录采用 `kg/`、`agent/`，生成配置和输出子目录使用相同功能名。原始目录名仅在来源清单的 `source` 字段保留，不参与运行。
- 实际教学运行发现原 tokenizer 兼容补丁覆盖 Transformers 已有属性时会返回无效 tokenizer；仅将五处补丁改为“属性不存在时添加”。此项运行时兼容修复及新目标哈希已记录在 `source_selection.json`；没有改模型提示、采样或检测政策。
- 原测试的目录示例改为 `/datasets/example-pairs` 和 `/runs/example-pairs/kg`，测试逻辑与断言关系保持不变。
- `source_manifest.json` 用于校验原Python/CWE文件；可编辑配置不在这个不可变清单中。
- `source_selection.json` 记录每个选入文件的相对来源、源/目标SHA-256及配置变更字段。不包含原配置正文或密码。

精炼脚本选择的是原始研究目录中的本地版本；已知它与另一个服务器历史副本的源码证据匹配分支不同。目前无法仅凭文件名唯一绑定论文最终指标的生成版本。本目录是来源明确的原始代码选择版，不把文件复制或冻结结果回放等同于重新推理复现论文。

原创检测代码、工具、文档与原创教学样例已由作者选择采用 MIT。第三方 CWE 数据来自原目录的 `1000.csv`，内容未改，继续适用上游条款。GPL论文样本与第三方资源不受根MIT覆盖，详见 `THIRD_PARTY_NOTICES.md`。本轮只准备本地材料与实际运行证据，没有发布仓库。
