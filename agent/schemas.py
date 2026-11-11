# -*- coding: utf-8 -*-
"""
schemas.py — Pydantic 数据模型定义
油气工业软件漏洞检测系统 KG-RAG Pipeline
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


# ============================================================
# 配置模型
# ============================================================


class LLMConfig(BaseModel):
    """单个 LLM 调用点的配置，支持远程 API 和本地 vLLM 两种后端"""

    # 后端选择
    backend: str = Field(
        default="api",
        description="后端类型: 'api'(远程OpenAI兼容API) 或 'vllm'(本地vLLM服务)",
    )

    # --- API 模式配置 ---
    api_base: str = Field(default="", description="OpenAI 兼容 API 的 Base URL")
    api_key: str = Field(default="", description="API 密钥")
    model: str = Field(default="", description="模型名称，如 gpt-4o")

    # --- vLLM 本地模式配置 ---
    model_path: str = Field(
        default="",
        description="HuggingFace 模型本地路径，如 /models/Qwen2.5-7B-Instruct",
    )
    vllm_port: int = Field(default=8100, description="vLLM 服务监听端口")
    gpu_memory_utilization: float = Field(
        default=0.9, description="vLLM GPU 显存利用率 (0.0~1.0)"
    )
    tensor_parallel_size: int = Field(
        default=1, description="vLLM 张量并行数（多卡时设置）"
    )
    max_model_len: int = Field(
        default=0, description="vLLM 最大序列长度（0=自动推断）"
    )

    # --- 通用配置 ---
    temperature: float = Field(default=0.0, description="采样温度")
    max_tokens: int = Field(default=1024, description="最大生成 Token 数")


# ============================================================
# Step 2: 双轨提取输出
# ============================================================


class TypedEntity(BaseModel):
    """
    类型化实体结构。
    """
    name: str = Field(description="实体或组件名称（英文）")
    type: str = Field(description="实体类型，必须是: 'Protocol', 'Variable', 'FunctionCall', 'System', 'Asset' 之一")
    importance: str = Field(description="重要度，必须是: 'High', 'Medium', 'Low' 之一")


class DualExtraction(BaseModel):
    """
    Step 2 的结构化输出 —— 类型化双轨语义提取与分类。

    由 LLM 通过 with_structured_output 生成，确保 JSON 稳定性。
    """

    entities: list[TypedEntity] = Field(
        default_factory=list,
        description=(
            "代码中涉及的 3-5 个最具代表性的核心业务名词或组件。每个名词需指定其类型与重要度。"
            "请将具体函数名泛化为通用的工业或计算机概念。"
            "绝不要提取通用的编程语言关键字（如 int, void, return）"
            "而应聚焦于关键系统动作、敏感API或行业专用名词。"
        )
    )
    semantic_summary: str = Field(
        description=(
            "一段对该代码业务逻辑的极其简短的自然语言总结（纯英文，1-2句），"
            "概述代码的核心功能和涉及的业务场景，但**严禁**提及任何安全性检查或防护判定。"
        )
    )
    domain: str = Field(
        default="Other",
        description=(
            "该代码所属的核心业务领域命名空间，"
            "必须是: 'Protocol', 'Simulation', 'Database', 'System', 'Other' 之一。"
        )
    )
    context_possible_cwes: list[str] = Field(
        default_factory=list,
        description=(
            "A list of possible CWE IDs (e.g. ['CWE-121', 'CWE-125']) related to the potential safety weaknesses "
            "that could hypothetically exist in this code context, considering variables, operations, and APIs used."
        )
    )


# ============================================================
# Step 3: 图谱检索结果
# ============================================================


class GraphWarning(BaseModel):
    """单条来自知识图谱的安全预警与防范审计契约"""

    entity: str = Field(description="匹配到的图谱业务节点名称")
    warning: str = Field(description="该节点关联的潜在漏洞警告原因")
    cwe_id: str = Field(description="关联的 CWE 漏洞编号")
    verification_contract: str = Field(
        default="",
        description="针对该漏洞的防御审计契约（代码需要满足什么防守条件才能被判为安全）",
    )


# ============================================================
# Step 5: 结构化漏洞诊断输出
# ============================================================


# ------------------------------------------------------------
# 级联诊断子步骤 Schema
# ------------------------------------------------------------

class BinaryDiagnosis(BaseModel):
    """阶段 A: 漏洞二分类判定（强制思维链推理缓冲）"""
    graph_warning_critique: str = Field(
        description=(
            "对检索到的知识图谱安全预警（如果存在）进行逐条批判性审查："
            "1. 评估该警告对应的场景/触发条件与当前代码功能是否真正契合？"
            "2. 代码是否已经实现了针对该警告的安全防守措施（如显式的边界检查、输入范围过滤、安全函数替换）？"
            "3. 判定该警告是否是字面相似但含义不符的无效噪音？如果是噪音，请明确说明理由并排除它的干扰。"
        )
    )
    code_logic_analysis: str = Field(
        description="对待审计代码的核心控制流与数据流进行具体的逻辑漏洞和内存安全审查，指出是否存在可利用的数据输入源与敏感操作。"
    )
    is_vulnerable: bool = Field(
        description="结合上述批判性审查与代码逻辑分析，最终判定代码中是否存在可被实际利用的安全漏洞（True=存在漏洞, False=安全）"
    )
    confidence: float = Field(
        description="诊断置信度，范围 0.0~1.0"
    )

class CWEDiagnosis(BaseModel):
    """阶段 B: 具体漏洞类型定位"""
    cwe_id: str = Field(
        default="",
        description="最能代表漏洞根本原因（Root Cause）的 Top 1 CWE 编号（如 'CWE-787'）",
    )
    vulnerability_type: str = Field(
        default="",
        description="漏洞类型的简要描述（如 '栈缓冲区溢出', '释放后使用'）",
    )

class ReportDiagnosis(BaseModel):
    """阶段 C: 报告生成"""
    explanation: str = Field(
        description="简短解释判定原因"
    )
    affected_lines: list[str] = Field(
        default_factory=list,
        description="受影响的关键代码行或代码片段摘录",
    )

# ------------------------------------------------------------

class DiagnosisResult(BaseModel):
    """
    Step 5 的结构化输出 —— 漏洞诊断结果汇总。

    由级联的 A, B, C 三个阶段汇总而成，包含完整的批判推理轨迹。
    """

    graph_warning_critique: str = Field(
        default="",
        description="对知识图谱安全预警的相关性与防守批判性审查",
    )
    code_logic_analysis: str = Field(
        default="",
        description="对代码核心数据流与控制流的安全逻辑审查",
    )
    is_vulnerable: bool = Field(
        description="该代码是否存在安全漏洞（True=存在漏洞, False=安全）"
    )
    confidence: float = Field(
        description="诊断置信度，范围 0.0~1.0"
    )
    cwe_id: str = Field(
        default="",
        description="最能代表漏洞根本原因（Root Cause）的 Top 1 CWE 编号（如 'CWE-787'），若安全则为空字符串",
    )
    vulnerability_type: str = Field(
        default="",
        description="漏洞类型的简要描述（如 '栈缓冲区溢出', '释放后使用'），若安全则为空字符串",
    )
    explanation: str = Field(
        description="详细的漏洞分析说明，包括漏洞成因、影响范围和修复建议",
    )
    affected_lines: list[str] = Field(
        default_factory=list,
        description="受影响的关键代码行或代码片段摘录",
    )


# ============================================================
# 样本数据模型
# ============================================================


class SampleInfo(BaseModel):
    """统一的样本元数据"""

    sample_id: str = Field(description="样本唯一标识（如 CVE-2024-34026, Sample_CWE787_001_vuln）")
    source_type: str = Field(description="样本来源类型: cve_vuln / cve_fixed / synthetic_vuln / synthetic_safe")
    label: str = Field(description="真实标签: vulnerable / safe")
    code: str = Field(description="待审计的 C++ 源代码内容")
    cwe_id: str = Field(default="", description="关联的 CWE 编号（若已知）")


# ============================================================
# 完整检测结果
# ============================================================


class DetectionResult(BaseModel):
    """单个样本的完整检测结果，包含所有中间产物"""

    sample_id: str = Field(description="样本唯一标识")
    source_type: str = Field(description="样本来源类型")
    ground_truth_label: str = Field(description="真实标签")
    ground_truth_cwe: str = Field(default="", description="真实 CWE 编号")
    pipeline_mode: str = Field(description="流水线模式: kg_rag / base_llm")

    # 中间产物
    extraction: Optional[DualExtraction] = Field(
        default=None, description="Step 2 双轨提取结果"
    )
    graph_warnings: list[GraphWarning] = Field(
        default_factory=list, description="Step 3 图谱检索到的安全预警"
    )
    assembled_prompt_preview: str = Field(
        default="", description="Step 4 组装的 Prompt 预览（截断前 500 字符）"
    )

    # 最终诊断
    diagnosis: Optional[DiagnosisResult] = Field(
        default=None, description="Step 5 结构化诊断结果"
    )

    # 状态
    status: str = Field(
        default="pending", description="处理状态: success / error"
    )
    error_message: str = Field(
        default="", description="错误信息（仅 status=error 时有值）"
    )
