# -*- coding: utf-8 -*-
"""
main_offline.py — 本地离线批处理运行器 (vLLM Native Engine)
油气工业软件漏洞检测系统 KG-RAG Pipeline

使用 vLLM 离线推理接口，实现多阶段批量化推理，充分释放 L20 显卡算力，解决 API 模式下的排队与重试雪崩问题。
支持 kg_rag 和 base_llm 两种模式。
"""

import argparse
import json
import logging
import os
import re
import sys
# 彻底解决 Windows 控制台下 GBK 编码输出表情或中文时的 UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
import time
from pathlib import Path
import yaml

# Monkeypatch Hugging Face transformers tokenizer to prevent vLLM initialization crash on slow tokenizers
try:
    import transformers
    import transformers.tokenization_utils_base
    import transformers.tokenization_utils
    
    # Define the property
    @property
    def all_special_tokens_extended(self):
        return self.all_special_tokens

    # Patch PreTrainedTokenizer
    if hasattr(transformers, "PreTrainedTokenizer") and not hasattr(transformers.PreTrainedTokenizer, "all_special_tokens_extended"):
        transformers.PreTrainedTokenizer.all_special_tokens_extended = all_special_tokens_extended
    if hasattr(transformers.tokenization_utils, "PreTrainedTokenizer") and not hasattr(transformers.tokenization_utils.PreTrainedTokenizer, "all_special_tokens_extended"):
        transformers.tokenization_utils.PreTrainedTokenizer.all_special_tokens_extended = all_special_tokens_extended

    # Patch PreTrainedTokenizerBase
    if hasattr(transformers, "PreTrainedTokenizerBase") and not hasattr(transformers.PreTrainedTokenizerBase, "all_special_tokens_extended"):
        transformers.PreTrainedTokenizerBase.all_special_tokens_extended = all_special_tokens_extended
    if hasattr(transformers.tokenization_utils_base, "PreTrainedTokenizerBase") and not hasattr(transformers.tokenization_utils_base.PreTrainedTokenizerBase, "all_special_tokens_extended"):
        transformers.tokenization_utils_base.PreTrainedTokenizerBase.all_special_tokens_extended = all_special_tokens_extended

    print("=== [MONKEYPATCH] Successfully patched transformers tokenizers ===")
except Exception as patch_err:
    print(f"=== [MONKEYPATCH ERROR] Failed to patch: {patch_err} ===")

from vllm import LLM, SamplingParams
from neo4j import GraphDatabase

from data_loader import DataLoader
from schemas import (
    DetectionResult,
    DiagnosisResult,
    DualExtraction,
    TypedEntity,
    GraphWarning,
    SampleInfo,
    BinaryDiagnosis,
    CWEDiagnosis,
    ReportDiagnosis,
)

# ============================================================
# 日志配置
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("kg_vuln_detect_offline")


class SemanticSimilarityModel:
    def __init__(self, model_path: str | None):
        self.enabled = False
        self._embedding_cache = {}
        if not model_path:
            logger.info("未配置向量相似度模型路径，将采用 TF-IDF 模式。")
            return
            
        try:
            import torch
            from transformers import AutoTokenizer, AutoModel
            self.torch = torch
            
            logger.info(f"正在加载向量相似度模型: {model_path} ...")
            self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
            self.model = AutoModel.from_pretrained(model_path, local_files_only=True)
            
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)
            self.model.eval()
            self.enabled = True
            logger.info(f"成功加载向量相似度模型: {model_path}，使用设备: {self.device}")
        except Exception as e:
            logger.warning(f"加载本地向量模型失败，将自动回退到 TF-IDF 模式。原因: {e}")

    def get_embedding(self, text: str):
        if not self.enabled:
            return None
            
        if text in self._embedding_cache:
            return self._embedding_cache[text]
            
        try:
            encoded_input = self.tokenizer(
                [text], 
                padding=True, 
                truncation=True, 
                max_length=512, 
                return_tensors='pt'
            ).to(self.device)
            
            with self.torch.no_grad():
                model_output = self.model(**encoded_input)
                cls_embedding = model_output[0][:, 0]
                dense_vector = self.torch.nn.functional.normalize(cls_embedding, p=2, dim=1)
                vector = dense_vector[0].cpu()
                
            self._embedding_cache[text] = vector
            return vector
        except Exception as e:
            logger.error(f"计算向量 embedding 异常: {e}")
            return None

    def calculate_similarity(self, text1: str, text2: str) -> float:
        if not self.enabled:
            return -1.0
            
        emb1 = self.get_embedding(text1)
        emb2 = self.get_embedding(text2)
        
        if emb1 is None or emb2 is None:
            return -1.0
            
        sim = self.torch.dot(emb1, emb2).item()
        return float(sim)


semantic_model = None


# 停用词/高噪词过滤 (精简版)
NOISE_WORDS = {
    # 虚词及代词
    "and", "or", "for", "with", "the", "this", "that", "from", "into", "using", 
    "about", "its", "their", "are", "was", "were", "been", "has", "have", "had",
    # 通用编程动作词与虚词
    "reads", "stores", "contains", "implements", "executes", "runs", "calls", 
    "processes", "handles", "manages", "defines", "creates", "updates", "deletes",
    "write", "read", "output", "input", "compile", "compilation", "compiler",
    "convert", "conversion", "parse", "parsing", "parser", "check", "checking",
    "validate", "validation", "verify", "verification", "test", "testing",
    "enable", "disable", "tuning", "external", "internal",
    # 极宽泛的名词
    "code", "program", "function", "functions", "class", "method", "methods", 
    "variable", "variables", "type", "types", "utility", "tool", "tools", 
    "argument", "arguments", "parameter", "parameters", "value", "values", 
    "key", "keys", "name", "names", "id", "ids", "info", "log", "logs", 
    "temp", "tempfile", "element", "property", "properties", "c", "dwr",
    # 极其宽泛的形容词
    "single", "multiple", "simple", "complex", "basic", "advanced", "default", 
    "custom", "standard", "generic", "specific", "common", "various", "different",
    "detail", "details", "options", "option", "settings", "setting", "config", 
    "configuration", "mode", "modes", "action", "actions", "operation", "operations",
    "int", "rec", "dir", "let", "tom", "fact", "err", "out", "val", "buf", "ptr", "num", "len"
}


# ============================================================
# CWE 语义倾向关联组映射与自动扩展字典
# ============================================================
CWE_EXPANSION_GROUPS = {
    # 内存安全相关组 (Memory Safety: CWE-119/120/121/122/125/787/129)
    "CWE-119": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-129"],
    "CWE-120": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-129"],
    "CWE-121": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-129"],
    "CWE-122": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-129"],
    "CWE-125": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-129"],
    "CWE-787": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-129"],
    "CWE-129": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-129"],

    # 资源生命周期相关组 (Lifecycle: CWE-415/416/401/400/775)
    "CWE-415": ["CWE-415", "CWE-416", "CWE-401", "CWE-400", "CWE-775"],
    "CWE-416": ["CWE-415", "CWE-416", "CWE-401", "CWE-400", "CWE-775"],
    "CWE-401": ["CWE-415", "CWE-416", "CWE-401", "CWE-400", "CWE-775"],
    "CWE-400": ["CWE-415", "CWE-416", "CWE-401", "CWE-400", "CWE-775"],
    "CWE-775": ["CWE-415", "CWE-416", "CWE-401", "CWE-400", "CWE-775"],

    # 输入验证/Web/注入组 (Web/Input/Injection: CWE-79/20/74/89/352/78/94/611)
    "CWE-79": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],
    "CWE-20": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],
    "CWE-74": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],
    "CWE-89": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],
    "CWE-352": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],
    "CWE-78": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],
    "CWE-94": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],
    "CWE-611": ["CWE-79", "CWE-20", "CWE-74", "CWE-89", "CWE-352", "CWE-78", "CWE-94", "CWE-611"],

    # 路径/文件访问相关组 (Path/File: CWE-22/434/59)
    "CWE-22": ["CWE-22", "CWE-434", "CWE-59"],
    "CWE-434": ["CWE-22", "CWE-434", "CWE-59"],
    "CWE-59": ["CWE-22", "CWE-434", "CWE-59"],

    # 数值计算与溢出组 (Numerical: CWE-190/369/682/191)
    "CWE-190": ["CWE-190", "CWE-369", "CWE-682", "CWE-191"],
    "CWE-369": ["CWE-190", "CWE-369", "CWE-682", "CWE-191"],
    "CWE-682": ["CWE-190", "CWE-369", "CWE-682", "CWE-191"],
    "CWE-191": ["CWE-190", "CWE-369", "CWE-682", "CWE-191"],

    # 并发与竞态条件组 (Concurrency: CWE-362/667/412)
    "CWE-362": ["CWE-362", "CWE-667", "CWE-412"],
    "CWE-667": ["CWE-362", "CWE-667", "CWE-412"],
    "CWE-412": ["CWE-362", "CWE-667", "CWE-412"],

    # 类型安全与数据转换组 (Type Safety: CWE-704/134/843)
    "CWE-704": ["CWE-704", "CWE-134", "CWE-843"],
    "CWE-134": ["CWE-704", "CWE-134", "CWE-843"],
    "CWE-843": ["CWE-704", "CWE-134", "CWE-843"]
}


def clean_and_expand_cwes(raw_cwes: list[str]) -> list[str]:
    """防御性清洗并扩展大模型返回的疑似 CWE 漏洞"""
    if not raw_cwes:
        return []
    
    cleaned_cwes = set()
    for cwe in raw_cwes:
        if not cwe:
            continue
        # 使用正则表达式提取类似 CWE-121 格式
        match = re.search(r'(?i)cwe[-_]?\d+', cwe)
        if match:
            cwe_clean = match.group(0).upper().replace('_', '-')
            num_match = re.search(r'\d+', cwe_clean)
            if num_match:
                cwe_id = f"CWE-{num_match.group(0)}"
                cleaned_cwes.add(cwe_id)
                # 语义扩展
                expanded = CWE_EXPANSION_GROUPS.get(cwe_id, [cwe_id])
                for exp in expanded:
                    cleaned_cwes.add(exp)
    return list(cleaned_cwes)


def sanitize_cwe_text(text: str) -> str:
    """消除文本描述中泄漏的 CWE 编号字样，防大模型偷懒盲从"""
    if not text:
        return ""
    # 1. 消除带括号的 (CWE-XXX) 或 (CWE XXX) 等
    text = re.sub(r'(?i)\s*\(\s*cwe[-_]?\d+\s*\)', '', text)
    # 2. 消除可能不带括号的 CWE-XXX
    text = re.sub(r'(?i)\bcwe[-_]?\d+\b', '', text)
    return text.strip()


# ============================================================
# 辅助解析函数
# ============================================================
def strip_markdown_json(text: str) -> str:
    """剥离 Markdown 代码块包裹，提取其中的 JSON 内容"""
    # 移除可能存在的思维链 <think>...</think>
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)

    # 匹配 ```json ... ``` 或 ``` ... ```
    pattern = r"```(?:json)?\s*\n?(.*?)\n?```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    else:
        text = text.strip()

    # 兜底提取：找第一个 '{' 到最后一个 '}'
    if not (text.startswith("{") and text.endswith("}")):
        json_match = re.search(r"(\{.*\})", text, re.DOTALL)
        if json_match:
            text = json_match.group(1).strip()

    return text


def parse_json_output(text: str, pydantic_model: type) -> type:
    """尝试将 LLM 文本输出解析为 Pydantic 数据模型，支持宽松字典解析、字段映射归一化及缺失字段自动修复"""
    cleaned = strip_markdown_json(text)
    
    # 1. 尝试标准 Pydantic 校验
    try:
        return pydantic_model.model_validate_json(cleaned)
    except Exception as standard_err:
        logger.info(f"标准 Pydantic 校验失败，尝试进行宽松解析与修复... 原因: {standard_err}")

    # 2. 标准解析失败，进入宽松的字典修复流程
    try:
        import json
        data = json.loads(cleaned)
        if isinstance(data, dict):
            # 字段同义词映射归一化
            if "is_vuln" in data and "is_vulnerable" not in data:
                data["is_vulnerable"] = data["is_vuln"]
            if "confidence_score" in data and "confidence" not in data:
                data["confidence"] = data["confidence_score"]
            if "cwe_ids" in data and "cwe_id" not in data:
                ids = data["cwe_ids"]
                if isinstance(ids, list) and len(ids) > 0:
                    data["cwe_id"] = ids[0]
                elif isinstance(ids, str):
                    data["cwe_id"] = ids

            # 补齐必填字段，填补默认值防止 Pydantic 异常
            for field_name, field_info in pydantic_model.model_fields.items():
                if field_name not in data:
                    field_type = field_info.annotation
                    if field_type == bool:
                        data[field_name] = False
                    elif field_type == float:
                        data[field_name] = 0.5
                    elif field_type == str:
                        data[field_name] = "Not provided by model (auto-filled)."
                    elif field_type == list or getattr(field_type, '__origin__', None) == list:
                        data[field_name] = []
                    else:
                        data[field_name] = None

            # 类型强转
            if "is_vulnerable" in data:
                val = data["is_vulnerable"]
                if isinstance(val, str):
                    data["is_vulnerable"] = val.lower() in ("true", "yes", "1", "vulnerable")
                elif isinstance(val, (int, float)):
                    data["is_vulnerable"] = bool(val)

            if "confidence" in data:
                try:
                    data["confidence"] = float(data["confidence"])
                except:
                    data["confidence"] = 0.5

            # 重新尝试 Pydantic 验证
            return pydantic_model.model_validate(data)
    except Exception as fallback_err:
        logger.warning(f"宽松解析与修复同样失败: {fallback_err} | 原始文本: {text!r}")

    raise ValueError("JSON parsing and auto-fix both failed")


# ============================================================
# 数据库查询逻辑
# ============================================================
def clean_mitigations(raw_mitigations: str) -> str:
    """清洗 Neo4j 中原始的 :: 格式缓解措施为干净的文本条目"""
    if not raw_mitigations or raw_mitigations.strip() == "nan" or not raw_mitigations.strip():
        return "      - No explicit mitigation rules specified. Verify standard secure coding practices."
        
    parts = re.split(r'::', raw_mitigations)
    clean_rules = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # 匹配 DESCRIPTION:
        match = re.search(r'DESCRIPTION:(.*)', part, re.DOTALL)
        if match:
            desc = match.group(1).strip()
            if desc and desc not in clean_rules:
                clean_rules.append(desc)
                
    if not clean_rules:
        # 兜底清洗，去除 :: 标签
        text = re.sub(r'::[A-Z0-9_]+:[A-Z0-9_]+:', ' ', raw_mitigations)
        text = re.sub(r'::', ' ', text).strip()
        return f"      - {text}"
        
    # 返回前 3 条最重要的规则
    return "\n".join([f"      - {rule}" for rule in clean_rules[:3]])

def calculate_cosine_similarity(text1: str, text2: str, node_idf: dict[str, float]) -> float:
    """计算两段文本之间的字面 TF-IDF 余弦相似度，利用图谱内置的 IDF 字典。"""
    import math
    tokens1 = [w for w in re.split(r'[^a-zA-Z0-9]', text1.lower()) if w]
    tokens2 = [w for w in re.split(r'[^a-zA-Z0-9]', text2.lower()) if w]
    
    sig1 = [t for t in tokens1 if t not in NOISE_WORDS and len(t) > 2]
    sig2 = [t for t in tokens2 if t not in NOISE_WORDS and len(t) > 2]
    
    if not sig1 or not sig2:
        return 0.0
        
    tf1 = {}
    for t in sig1:
        tf1[t] = tf1.get(t, 0.0) + 1.0
    tf2 = {}
    for t in sig2:
        tf2[t] = tf2.get(t, 0.0) + 1.0
        
    vec1 = {}
    vec2 = {}
    words = set(tf1.keys()) | set(tf2.keys())
    
    for w in words:
        idf_val = node_idf.get(w, 1.0)
        vec1[w] = tf1.get(w, 0.0) * idf_val
        vec2[w] = tf2.get(w, 0.0) * idf_val
        
    dot_product = sum(vec1[w] * vec2[w] for w in words)
    mag1 = math.sqrt(sum(val ** 2 for val in vec1.values()))
    mag2 = math.sqrt(sum(val ** 2 for val in vec2.values()))
    
    if mag1 == 0.0 or mag2 == 0.0:
        return 0.0
        
    return dot_product / (mag1 * mag2)

domain_namespace_cache = {}

def query_graph_warnings(
    driver, db_name: str, candidate_nodes: list[str], node_idf: dict[str, float], 
    entities: list[TypedEntity], semantic_summary: str, domain: str = "Other",
    context_possible_cwes: list[str] = None
) -> list[GraphWarning]:
    """根据提取的功能语义词和摘要，执行三关防御图谱检索并在 Python 侧进行过滤重排"""
    if not candidate_nodes:
        return []

    # ----- 拓扑双向锚定约束：清洗与扩展可能涉及的 CWE 弱点 -----
    possible_cwes = clean_and_expand_cwes(context_possible_cwes)
    logger.info(f"Step 3 拓扑双向锚定约束 | 原始预测 CWE: {context_possible_cwes} | 语义扩展后 CWE 范围: {possible_cwes}")

    # ----- 第二关: 获取当前命名空间的候选节点 -----
    candidates_to_score = candidate_nodes
    domain_key = domain.strip().lower() if domain else "other"
    if domain_key in domain_namespace_cache:
        namespace_nodes = domain_namespace_cache[domain_key]
        logger.info(f"第二关命名空间限制 (从缓存中加载) | 限制范围为 {len(namespace_nodes)} 个节点 (Domain={domain})")
    else:
        namespace_nodes = set()
        try:
            with driver.session(database=db_name) as session:
                query_namespace = """
                MATCH (e:Entity)-[:BELONGS_TO]->(d:Domain)
                WHERE toLower(d.name) = toLower($domain) OR d.name IN ['System', 'Other']
                RETURN distinct e.name as name
                """
                res = session.run(query_namespace, domain=domain)
                for record in res:
                    if record["name"]:
                        namespace_nodes.add(record["name"])
            domain_namespace_cache[domain_key] = namespace_nodes
            logger.info(f"第二关命名空间限制 (已查询数据库并存入缓存) | 限制范围为 {len(namespace_nodes)} 个节点 (Domain={domain})")
        except Exception as e:
            logger.error(f"第二关查询 Neo4j 异常: {e}，将回退到全局检索")

    if namespace_nodes:
        candidates_to_score = list(namespace_nodes)

    # ----- 第一关: 编译查询显著词并过滤低重要度实体 -----
    sig_entity_tokens = set()
    for e in entities:
        if e.importance.lower() == "low" and e.type.lower() in ("variable", "system"):
            logger.info(f"第一关阻断 | 过滤低重要度词汇: {e.name} (type={e.type})")
            continue
            
        name_lower = e.name.lower()
        tokens = [w for w in re.split(r'[^a-zA-Z0-9]', name_lower) if w]
        for t in tokens:
            if t not in NOISE_WORDS and len(t) > 2:
                sig_entity_tokens.add(t)

    union_tokens = sig_entity_tokens

    if not union_tokens:
        logger.info("经过第一关阻断过滤后，待检索实体词为空，触发饥饿保护")
        return []

    scores_map = {}
    exact_matched_names = set()  # 记录精确匹配的数据库节点名称
    for name in candidates_to_score:
        name_lower = name.lower()
        
        # 检查是否与提取的某实体名完全一致（忽略大小写和前后空格）
        is_exact = False
        for e in entities:
            ent_name = e.name.strip().lower()
            if ent_name == name_lower:
                is_exact = True
                break
                
        tokens = [w for w in re.split(r'[^a-zA-Z0-9]', name_lower) if w]
        sig_tokens = set(t for t in tokens if t not in NOISE_WORDS and len(t) > 2)
        
        if not sig_tokens:
            continue
            
        # 双向软子串 Token 匹配
        intersection = set()
        for q_tok in union_tokens:
            for c_tok in sig_tokens:
                if q_tok == c_tok:
                    intersection.add(c_tok)
                elif (q_tok in c_tok or c_tok in q_tok) and min(len(q_tok), len(c_tok)) >= 3:
                    intersection.add(c_tok)

        if intersection:
            # 实体打分并加入平滑后的覆盖度惩罚（取开方），防止短查询下多词实体被过度惩罚
            score = sum(node_idf.get(w, 0.0) for w in intersection)
            coverage_ratio = len(intersection) / len(sig_tokens)
            final_score = score * (coverage_ratio ** 0.5)
            
            # 若是精确匹配，直接赋予最高匹配分，并记录
            if is_exact:
                final_score += 50.0
                exact_matched_names.add(name)
                
            if final_score > 0.0:
                scores_map[name] = final_score

    # 设定打分平滑后的动态自适应阈值，避免硬编码过滤长短实体的不公平性
    max_score = max(scores_map.values()) if scores_map else 0.0
    SCORE_CUTOFF = max(1.0, max_score * 0.6)
    if max_score < SCORE_CUTOFF:
        logger.info(f"最高匹配分值 {max_score:.2f} 低于动态阈值 {SCORE_CUTOFF:.2f}，触发安全预警饥饿保护（空结果）")
        return []

    # 按照分值由大到小排序，最多前 3 个最相关的节点
    matched_names = [
        k for k in sorted(scores_map.keys(), key=lambda k: scores_map[k], reverse=True)
        if scores_map[k] >= SCORE_CUTOFF
    ][:3]

    if not matched_names:
        return []

    logger.info(f"Step 3 实体对齐匹配到节点: {[(name, f'{scores_map[name]:.2f}') for name in matched_names]}")

    # 提取实际命中的精确匹配节点列表，使用大小写与去空格不敏感方式，用于在 Cypher 查询中豁免 CWE 过滤
    exact_matched_list = [
        name for name in matched_names 
        if name.strip().lower() in {e.strip().lower() for e in exact_matched_names}
    ]

    # 使用 CALL (name) 限制单个节点返回的预警数，确保多样性并保持 Python 端的打分顺序，采用 Neo4j 2026 最新作用域语法，并进行单向拓扑 CWE 隔离与层级继承多跳检索
    query = """
    UNWIND $matched_names AS name
    CALL (name) {
        MATCH (n:OGL_Node)-[:INDUSTRIAL_LOGIC*0..1]->(v:OGL_Node)-[r:POTENTIAL_WEAKNESS]->(c)
        WHERE n.name = name AND (c:CWE OR c:PotentialWeakness)
        
        OPTIONAL MATCH (cwe_node:CWE)
        WHERE cwe_node.id = coalesce(c.id, c.cwe_id, "")
        
        OPTIONAL MATCH (cwe_node)-[:CHILD_OF*0..2]->(parent:CWE)
        
        WITH n, v, r, c, 
             collect(distinct coalesce(parent.id, "")) + coalesce(c.id, c.cwe_id, "") AS cwe_family
        
        WHERE n.name IN $exact_matched_list
           OR $possible_cwes IS NULL 
           OR size($possible_cwes) = 0 
           OR any(cwe IN cwe_family WHERE cwe IN $possible_cwes)
           
        RETURN n.name AS Entity, 
               CASE 
                   WHEN n = v THEN coalesce(r.reason, c.name, "Potential vulnerability risk")
                   ELSE "[Downstream Risk | Dependency: " + v.name + "] " + coalesce(r.reason, c.name, "Potential vulnerability risk")
               END AS Warning,
               coalesce(c.id, c.cwe_id, "") AS CWE_ID,
               coalesce(c.verification_contract, c.mitigations, "") AS Mitigations
        LIMIT 3
    }
    RETURN Entity, Warning, CWE_ID, Mitigations
    """
    
    raw_warnings = []
    try:
        with driver.session(database=db_name) as session:
            result = session.run(
                query, 
                matched_names=matched_names, 
                possible_cwes=possible_cwes,
                exact_matched_list=exact_matched_list
            )
            for record in result:
                raw_mitigations = record["Mitigations"]
                clean_contract = clean_mitigations(raw_mitigations)
                raw_warnings.append(
                    GraphWarning(
                        entity=record["Entity"],
                        warning=record["Warning"],
                        cwe_id=record["CWE_ID"],
                        verification_contract=clean_contract,
                    )
                )
    except Exception as e:
        logger.error(f"Neo4j 图谱查询异常: {e}")
        return []

    # ----- 第三关: 双工语义相似度重排过滤 (Cross-Encoder Filter / Semantic Match) -----
    filtered_warnings = []
    for w in raw_warnings:
        # 仅对比业务语义与工业预警逻辑 (w.warning)，避免安全防范契约内容稀释相似度
        match_target = w.warning if w.warning else ""
        
        is_exact = w.entity.strip().lower() in {e.strip().lower() for e in exact_matched_names}
        global semantic_model
        if semantic_model and semantic_model.enabled:
            sim = semantic_model.calculate_similarity(semantic_summary, match_target)
            # BGE-M3 向量相似度：精确匹配豁免，非精确匹配设定为 0.52
            SIMILARITY_THRESHOLD = 0.00 if is_exact else 0.52
        else:
            sim = calculate_cosine_similarity(semantic_summary, match_target, node_idf)
            SIMILARITY_THRESHOLD = 0.00 if is_exact else 0.10
        
        if sim >= SIMILARITY_THRESHOLD:
            filtered_warnings.append(w)
            logger.info(f"第三关通过 | 警告: [{w.entity}] (相似度={sim:.4f} >= {SIMILARITY_THRESHOLD}, 模型启用={bool(semantic_model and semantic_model.enabled)})")
        else:
            logger.info(f"第三关过滤 | 抛弃噪声预警: [{w.entity}] (相似度={sim:.4f} < {SIMILARITY_THRESHOLD}, 模型启用={bool(semantic_model and semantic_model.enabled)})")

    # ----- 新增: CWE 语义关联组消噪过滤 (CWE Association Cluster Filter) -----
    # 如果检索到的警告 CWE 与模型最初预测的潜在 CWE 处于完全不同的关联类簇中，直接作为噪音滤除
    filtered_by_association = []
    if context_possible_cwes:
        # 获取所有预测 CWE 的语义倾向关联组内成员
        allowed_cwes = set()
        for p_cwe in context_possible_cwes:
            match = re.search(r'(?i)cwe[-_]?\d+', p_cwe)
            if match:
                cwe_clean = match.group(0).upper().replace('_', '-')
                num_match = re.search(r'\d+', cwe_clean)
                if num_match:
                    cwe_id = f"CWE-{num_match.group(0)}"
                    allowed_cwes.add(cwe_id)
                    expanded = CWE_EXPANSION_GROUPS.get(cwe_id, [cwe_id])
                    for exp in expanded:
                        allowed_cwes.add(exp)
        
        exact_match_fallback = []
        for w in filtered_warnings:
            w_cwe = w.cwe_id.strip() if w.cwe_id else ""
            is_exact = w.entity.strip().lower() in {e.strip().lower() for e in exact_matched_names}
            
            if not w_cwe:
                filtered_by_association.append(w)
                continue
                
            # 清洗 w_cwe 为标准格式
            w_match = re.search(r'(?i)cwe[-_]?\d+', w_cwe)
            if w_match:
                digits_match = re.search(r'\d+', w_match.group(0))
                digits = digits_match.group(0) if digits_match else ""
                w_cwe_id = f"CWE-{digits}"
            else:
                w_cwe_id = w_cwe
            
            if w_cwe_id in allowed_cwes:
                filtered_by_association.append(w)
            else:
                if is_exact:
                    exact_match_fallback.append(w)
                    logger.info(f"CWE关联组过滤 (暂存精确匹配作兜底) | [{w.entity}] (CWE={w_cwe_id} 与预测范围不匹配)")
                else:
                    logger.info(f"CWE关联组过滤 | 抛弃跨类别噪音警告: [{w.entity}] (CWE={w_cwe_id} 与预测范围不匹配)")
                    
        # 兜底机制：如果完全过滤光了，退回保留精确匹配结果
        if not filtered_by_association and exact_match_fallback:
            filtered_by_association = exact_match_fallback
            logger.info(f"CWE关联组过滤兜底触发 | 保留精确匹配警告数量: {len(filtered_by_association)}")
    else:
        filtered_by_association = filtered_warnings

    # ----- 第四关: CWE 多样性阻断 (CWE Diversity Cutoff) -----
    # 限制同一个样本最多只能包含 2 种不同 CWE 类型的警告，防止大模型决策混淆
    final_warnings = []
    seen_cwes = set()
    for w in filtered_by_association:
        cwe_id = w.cwe_id.strip() if w.cwe_id else ""
        if cwe_id:
            if cwe_id not in seen_cwes:
                if len(seen_cwes) >= 2:
                    logger.info(f"CWE多样性阻断 | 过滤多余的CWE警告: [{w.entity}] (CWE={cwe_id})")
                    continue
                seen_cwes.add(cwe_id)
        final_warnings.append(w)

    # ----- 新增: 对非精确匹配 (not is_exact) 的警告进行 Checklist 降维重写 -----
    for w in final_warnings:
        is_exact = w.entity.strip().lower() in {e.strip().lower() for e in exact_matched_names}
        if not is_exact:
            w.warning = f"Protocol-level architecture reference context found for [{w.entity}]. Please verify overall compliance."
            w.verification_contract = (
                "1. Verify that all input fields from this protocol branch have explicit upper/lower boundary constraints.\n"
                "2. Ensure no hardcoded magic balances or sizes are trusted blindly during buffer allocations."
            )

    logger.info(f"Step 3 完成 | 原始检索 {len(raw_warnings)} 条 -> 重排后 {len(filtered_warnings)} 条 -> 多样性阻断后保留 {len(final_warnings)} 条预警")
    return final_warnings


# ============================================================
EXTRACTION_SYSTEM = (
    "You are a senior security analysis expert for Oil & Gas industrial software. "
    "Your task is to perform structured entity extraction and domain classification on the given C/C++ code.\n\n"
    "You MUST strictly follow these requirements to extract information:\n"
    "1. **entities**: Extract 3-5 core business concepts or component names. "
    "For each entity, specify:\n"
    "   - `name`: The exact name of the concept (in English, lowercased, e.g. 'modbus', 'abaqus', 'socket', 'memcpy').\n"
    "     ⚠️ CRITICAL: DO NOT extract generic programming keywords, trivial single-letter variables, or generic data structure/math/container/attribute terms (e.g., 'int', 'char', 'void', 'return', 'if', 'for', 'x', 'y', 'i', 'p', 'map', 'list', 'vector', 'distance', 'level', 'value', 'data', 'key', 'name', 'status', 'type', 'index', 'size', 'len', 'count'). You may extract core concepts like 'buffer', 'socket', 'file', or 'pointer' if they are the central targets of memory/input operations, along with protocol, module, structure, or security-critical API calls (e.g., 'modbus_hdr', 'memcpy', 'recv').\n"
    "   - `type`: The type of entity, must be one of: 'Protocol', 'Variable', 'FunctionCall', 'System', 'Asset'.\n"
    "   - `importance`: The importance of the concept to code safety, must be one of: 'High', 'Medium', 'Low'.\n"
    "2. **semantic_summary**: Write a very brief (1-2 sentences) natural language summary of the code's business scenario in PURE ENGLISH (e.g., 'This code parses Modbus responses'). DO NOT describe any safety checks or validate correctness.\n"
    "3. **domain**: Classify the overall domain of the code. Must be one of: 'Protocol', 'Simulation', 'Database', 'System', 'Other'.\n"
    "4. **context_possible_cwes**: Identify a list of 1-4 standard CWE IDs (e.g., ['CWE-121', 'CWE-125']) related to the potential safety weaknesses "
    "that could hypothetically exist in this code context, considering the variables, operations, and APIs used (e.g., CWE-119/121/125/787/129 for memory/buffer operations; CWE-79/20/74/89/352 for web operations; CWE-22/434/59 for file/path operations; CWE-415/416/401 for resource lifecycle).\n\n"
    "❗❗❗ CRITICAL: You must output ONLY a pure JSON object. ALL content MUST be in PURE ENGLISH. DO NOT include any Chinese characters or Markdown formatting.\n"
    "Output Format Example:\n"
    '{"entities": [{"name": "modbus", "type": "Protocol", "importance": "High"}, {"name": "memcpy", "type": "FunctionCall", "importance": "High"}], '
    '"semantic_summary": "This code implements Modbus protocol response processing.", '
    '"domain": "Protocol", '
    '"context_possible_cwes": ["CWE-121", "CWE-125"]}'
)


DIAGNOSIS_SYSTEM_5A = (
    "You are an independent security auditor for Oil & Gas Industrial Control Systems (ICS/SCADA/PLC).\n"
    "Your task is to objectively determine whether the provided C/C++ code contains active, exploitable security vulnerabilities.\n\n"
    "⚠️ IMPORTANT: The code you receive is EQUALLY LIKELY to be SAFE or VULNERABLE. "
    "Approximately half of the samples are safe (patched/fixed) code. Do NOT assume the code is vulnerable by default.\n\n"
    "**Auditing Steps (You must perform these in order)**:\n"
    "1. **graph_warning_critique**: Critically evaluate each provided Knowledge Graph Verification Contract (if any) against the code. "
    "Identify if a contract is a word-matching noise (e.g. matching a grid solver warning on an OSGi plugin). "
    "If it is noise, explicitly state so and ignore it. "
    "If it is valid, check if the code implements the required defensive check (e.g., bounds checking, length limits). "
    "If a warning is fully defended, state that it is satisfied (SAFE).\n"
    "Additionally, do NOT automatically adopt the CWE ID of a safety warning if it differs from the C/C++ code's actual root cause (e.g., if the code has an XSS vulnerability, the correct CWE is CWE-79, even if a warning mentions JSON deserialization CWE-502).\n"
    "2. **code_logic_analysis**: Conduct an independent check of the code's data flow and control flow to identify logical flaws or memory safety bugs.\n"
    "3. **is_vulnerable**: Set to true ONLY if there is a specific, exploitable vulnerability that has NO protective measures in the code.\n\n"
    "❗❗❗ CRITICAL: Output ONLY a pure JSON object. No markdown, no extra text.\n"
    "Output Format Example:\n"
    '{\n'
    '  "graph_warning_critique": "Warning 1 is a word-matching noise because the code is an XML parser, not a mesh solver. Warning 2 is satisfied because the length check at line 12 restricts input size to 256.",\n'
    '  "code_logic_analysis": "The code validates length before copy and uses bounds checking. No other vulnerabilities found.",\n'
    '  "is_vulnerable": false,\n'
    '  "confidence": 0.95\n'
    '}'
)

DIAGNOSIS_SYSTEM_5A_BASE_LLM = (
    "You are an independent security auditor for Oil & Gas Industrial Control Systems (ICS/SCADA/PLC).\n"
    "Your task is to objectively determine whether the provided C/C++ code contains active, exploitable security vulnerabilities.\n\n"
    "⚠️ IMPORTANT: The code you receive is EQUALLY LIKELY to be SAFE or VULNERABLE. "
    "Approximately half of the samples are safe (patched/fixed) code. Do NOT assume the code is vulnerable by default.\n\n"
    "**Auditing Steps (You must perform these in order)**:\n"
    "1. **graph_warning_critique**: Output 'Not applicable in base_llm mode' since no Knowledge Graph warnings are provided.\n"
    "2. **code_logic_analysis**: Conduct an independent check of the code's data flow and control flow to identify logical flaws or memory safety bugs.\n"
    "3. **is_vulnerable**: Set to true ONLY if there is a specific, exploitable vulnerability that has NO protective measures in the code.\n\n"
    "❗❗❗ CRITICAL: Output ONLY a pure JSON object. No markdown, no extra text.\n"
    "Output Format Example:\n"
    "{\n"
    '  "graph_warning_critique": "Not applicable in base_llm mode.",\n'
    '  "code_logic_analysis": "The code validates length before copy and uses bounds checking. No other vulnerabilities found.",\n'
    '  "is_vulnerable": false,\n'
    '  "confidence": 0.95\n'
    "}"
)

DIAGNOSIS_SYSTEM_5B = (
    "You are a top-tier security code reviewer.\n"
    "The provided C/C++ code has already been confirmed to contain a security vulnerability.\n"
    "Your task is to identify the SINGLE most likely CWE ID that represents the ROOT CAUSE of the vulnerability.\n\n"
    "**Candidate CWE Pool (from Knowledge Graph & Model Predictions)**:\n"
    "{cwe_candidates}\n\n"
    "**Instructions**:\n"
    "1. Analyze the C/C++ code structure and data/control flow.\n"
    "2. Prioritize selecting the root cause CWE ID from the Candidate CWE Pool above if it aligns with the code logic.\n"
    "3. Only deduce a different CWE ID outside the pool if the candidates are completely incorrect.\n\n"
    "❗❗❗ CRITICAL: Output ONLY a pure JSON object. No markdown, no extra text.\n"
    "Output Format Example:\n"
    '{{"cwe_id": "CWE-121", "vulnerability_type": "Stack-based Buffer Overflow"}}'
)

DIAGNOSIS_SYSTEM_5C = (
    "You are a top-tier security code reviewer.\n"
    "Your task is to provide a brief explanation and extract affected lines for the provided code.\n\n"
    "**Instructions**:\n"
    "1. Reason internally in English, but output the final 'explanation' field in Chinese for readability.\n"
    "2. Keep the explanation concise and to the point.\n"
    "3. If the code is marked as SAFE, provide a one-sentence explanation of why it is safe, and set affected_lines to an empty list [].\n"
    "4. If the code is marked as VULNERABLE, extract the specific problematic lines into 'affected_lines', and explain the root cause concisely.\n\n"
    "❗❗❗ CRITICAL: Output ONLY a pure JSON object. No markdown, no extra text.\n"
    "Output Format Examples:\n"
    '{"explanation": "该代码在解析数据时，直接使用了未经验证的输入长度...", "affected_lines": ["strcpy(buf, input)"]}\n'
    '{"explanation": "该代码使用了 snprintf 替代 sprintf，并对输入长度进行了显式检查，成功防御了潜在的溢出攻击。", "affected_lines": []}'
)


# ============================================================
# 离线运行引擎
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="油气工业软件漏洞检测系统 — 本地离线批处理运行器 (vLLM Native)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="配置文件路径（默认: config.yaml）",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="测试模式：只取 10 个样本测试",
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=32,
        help="vLLM 推理的并发批尺寸 (默认: 32)",
    )
    args = parser.parse_args()

    # Load configuration
    config_path = Path(__file__).parent / args.config
    if not config_path.exists():
        logger.error(f"配置文件不存在: {config_path}")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # 初始化本地向量相似度模型 (如果有配置且模式为 kg_rag)
    embedding_conf = config.get("llm", {}).get("embedding", {})
    embedding_model_path = embedding_conf.get("model_path", None)
    
    global semantic_model
    if config.get("experiment", {}).get("pipeline_mode", "kg_rag") == "kg_rag":
        semantic_model = SemanticSimilarityModel(embedding_model_path)
    else:
        semantic_model = SemanticSimilarityModel(None)

    paths = config["paths"]
    pipeline_mode = config["experiment"]["pipeline_mode"]
    runtime = config["runtime"]

    # 1. 显存优化参数，根据 L20 的 48GB 显存配置合适大小
    llm_conf = config["llm"]["extraction"]  # 获取 vllm 部分的配置
    model_path = llm_conf.get("model_path", "")
    gpu_memory_utilization = llm_conf.get("gpu_memory_utilization", 0.9)
    tensor_parallel_size = llm_conf.get("tensor_parallel_size", 1)
    max_model_len = llm_conf.get("max_model_len", 0)
    if max_model_len <= 0:
        max_model_len = 32768  # 给 14B 模型分配较大的窗口

    # 2. 加载样本
    logger.info("正在加载样本数据...")
    loader = DataLoader(
        cve_dir=paths["cve_dir"],
        synthetic_dir=paths["synthetic_dir"],
    )
    samples = loader.load_all()
    if args.test:
        import random
        samples = random.sample(samples, min(10, len(samples)))
        logger.info(f"【测试模式】随机选取 {len(samples)} 个样本进行测试")

    if not samples:
        logger.error("未加载到任何样本，退出")
        sys.exit(1)

    # 确定动态输出文件名 (按照 pipeline_mode 区分)
    output_dir = Path(paths["output_dir"])
    config_result_file = runtime["result_file"]
    if config_result_file.endswith(".jsonl"):
        base_name = config_result_file[:-6]
        result_filename = f"{base_name}_{pipeline_mode}.json"
    elif config_result_file.endswith(".json"):
        base_name = config_result_file[:-5]
        result_filename = f"{base_name}_{pipeline_mode}.json"
    else:
        result_filename = f"{config_result_file}_{pipeline_mode}.json"
    result_file = output_dir / result_filename

    # 读取已有成功记录，支持断点续检与错误重检
    successful_results = {}
    error_count_in_file = 0
    if not args.test and result_file.exists():
        logger.info(f"正在扫描已有结果文件: {result_file} ...")
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                records_list = json.load(f)
                for record_dict in records_list:
                    if record_dict.get("pipeline_mode") != pipeline_mode:
                        continue
                    res_obj = DetectionResult.model_validate(record_dict)
                    if res_obj.status == "success":
                        successful_results[res_obj.sample_id] = res_obj
                    else:
                        error_count_in_file += 1
        except Exception as e:
            logger.warning(f"读取已有结果文件失败 (可能格式损坏或为空): {e}")
        logger.info(f"断点续检: 已加载已成功样本 {len(successful_results)} 个。原结果文件中失败样本 {error_count_in_file} 个。")

    # 过滤出待检测样本 (从未运行过的，或者之前运行报错的)
    pending_samples = []
    for s in samples:
        if s.sample_id in successful_results:
            continue
        pending_samples.append(s)

    logger.info(f"待检测样本总数: {len(pending_samples)} 个 (包含之前报错重检和未检样本)")
    if not pending_samples:
        logger.info("所有样本均已检测成功，无需重新运行！")
        sys.exit(0)

    # 3. 初始化 Neo4j
    neo4j_driver = None
    candidate_nodes = []
    node_idf = {}
    if pipeline_mode == "kg_rag":
        logger.info("正在连接 Neo4j 数据库...")
        neo4j_conf = config["neo4j"]
        neo4j_driver = GraphDatabase.driver(
            neo4j_conf["uri"],
            auth=(neo4j_conf["username"], neo4j_conf["password"]),
        )
        neo4j_db = neo4j_conf.get("database", "neo4j")

        # 加载图谱节点并计算 IDF 权重，用于 Python 端语义对齐
        import math
        logger.info("正在从 Neo4j 数据库加载候选节点并计算 IDF 权重...")
        try:
            with neo4j_driver.session(database=neo4j_db) as session:
                q = "MATCH (n:OGL_Node) RETURN distinct n.name as name"
                res = session.run(q)
                candidate_nodes = [record['name'] for record in res if record['name']]
            
            NOISE_WORDS = {
                "json", "xml", "http", "https", "face", "vertex", "mesh", "grid", "block", 
                "status", "file", "data", "buffer", "string", "array", "keyvaluepair",
                "c", "dwr", "value", "key", "name", "id", "type", "info", "log", 
                "temp", "tempfile", "process", "thread", "element", "property",
                "web", "interface", "commands", "button", "system", "application", 
                "client", "library", "server", "servers", "file", "files", "utility", 
                "administration", "manual", "kit", "licenses", "license", "user", 
                "parameter", "hostid", "hostids", "service", "services", "activation", 
                "active", "filter", "detail", "details", "options", "option", "settings",
                "setting", "config", "configuration", "mode", "modes", "action", "actions",
                "operation", "operations", "and", "or", "for", "with", "the", "this", "that",
                "from", "into", "using", "reads", "stores", "contains", "implements", 
                "executes", "runs", "calls", "processes", "handles", "manages",
                "command", "commands", "line", "true", "false", "argument", "arguments", 
                "option", "options", "enable", "disable", "tuning", "external", "code", 
                "compilation", "compiler", "compile", "write", "read", "output", "input",
                "function", "functions", "class", "method", "methods", "variable", "variables", 
                "type", "types", "convert", "conversion", "utility", "tool", "tools", "command-line",
                "single", "multiple", "simple", "complex", "basic", "advanced", "default", 
                "custom", "standard", "generic", "specific", "common", "various", "different"
            }
            
            corpus_size = len(candidate_nodes)
            word_doc_counts = {}
            for name in candidate_nodes:
                name_lower = name.lower()
                tokens = [w for w in re.split(r'[^a-zA-Z0-9]', name_lower) if w]
                sig_tokens = set(t for t in tokens if t not in NOISE_WORDS and len(t) > 2)
                for t in sig_tokens:
                    word_doc_counts[t] = word_doc_counts.get(t, 0) + 1
                    
            for word, count in word_doc_counts.items():
                node_idf[word] = math.log((corpus_size - count + 0.5) / (count + 0.5) + 1)
                
            logger.info(f"成功加载 {corpus_size} 个候选节点，构建 {len(node_idf)} 个显著词的 IDF 索引")
        except Exception as e:
            logger.error(f"加载图谱并构建 IDF 索引失败: {e}")

    # 4. 初始化本地 vLLM 离线推理引擎
    logger.info(f"正在加载 vLLM 离线模型引擎. 模型路径: {model_path} ...")
    os.environ["VLLM_USE_V1"] = "0"  # 确保稳定版 V0 引擎
    llm = LLM(
        model=model_path,
        tensor_parallel_size=tensor_parallel_size,
        gpu_memory_utilization=gpu_memory_utilization,
        max_model_len=max_model_len,
        trust_remote_code=True,
        enforce_eager=True,
        enable_prefix_caching=True,  # 👈 核心：开启前缀缓存，完全加速后续阶段的推理
    )

    # 定义 vLLM 生成参数
    sampling_params_json = SamplingParams(
        temperature=0.0,
        max_tokens=4096,
    )
    
    # 5C 可以适当大点 max_tokens 以容纳中文说明
    sampling_params_report = SamplingParams(
        temperature=0.2,
        max_tokens=4096,
    )

    # 最终结果存储 (仅对待检测样本进行分配)
    results_dict: dict[str, DetectionResult] = {}
    for s in pending_samples:
        results_dict[s.sample_id] = DetectionResult(
            sample_id=s.sample_id,
            source_type=s.source_type,
            ground_truth_label=s.label,
            ground_truth_cwe=s.cwe_id,
            pipeline_mode=pipeline_mode,
        )

    start_total_time = time.time()

    # ============================================================
    # 阶段一：Step 2 双轨语义提取（仅在 kg_rag 模式下生效）
    # ============================================================
    if pipeline_mode == "kg_rag":
        logger.info(f"[STAGE 1/5] 批量语义提取 (Step 2) 中，样本数: {len(pending_samples)} ...")
        conversations = []
        for s in pending_samples:
            clean_code = s.code.strip().replace("\r\n", "\n")
            conv = [
                {"role": "system", "content": EXTRACTION_SYSTEM},
                {"role": "user", "content": f"Please analyze the following C/C++ code and output the result in pure JSON format:\n\n```cpp\n{clean_code}\n```"}
            ]
            conversations.append(conv)

        # 批量调用 vLLM
        outputs = llm.chat(
            conversations,
            sampling_params=sampling_params_json,
            use_tqdm=True
        )

        # 解析 Step 2 结果
        for idx, out in enumerate(outputs):
            sid = pending_samples[idx].sample_id
            res_text = out.outputs[0].text
            try:
                extraction = parse_json_output(res_text, DualExtraction)
                results_dict[sid].extraction = extraction
            except Exception as e:
                logger.error(f"样本 {sid} Step 2 语义解析异常: {e}")
                results_dict[sid].status = "error"
                results_dict[sid].error_message = f"Step 2 JSON parse error: {e}"

        # ============================================================
        # 阶段二：Step 3 知识图谱检索 (Neo4j)
        # ============================================================
        logger.info(f"[STAGE 2/5] 批量查询图数据库 (Step 3) ...")
        for s in pending_samples:
            res = results_dict[s.sample_id]
            if res.status == "error" or not res.extraction:
                continue
            warnings = query_graph_warnings(
                neo4j_driver, neo4j_db, candidate_nodes, node_idf, 
                res.extraction.entities, res.extraction.semantic_summary, res.extraction.domain,
                res.extraction.context_possible_cwes
            )
            res.graph_warnings = warnings

    # ============================================================
    # 阶段三：Step 5a 漏洞二分类诊断
    # ============================================================
    logger.info(f"[STAGE 3/5] 批量二分类漏洞诊断 (Step 5a) ...")
    conversations_5a = []
    valid_samples_5a = []

    for s in pending_samples:
        res = results_dict[s.sample_id]
        if res.status == "error":
            continue

        clean_code = s.code.strip().replace("\r\n", "\n")
        # 组装超级 Prompt
        if pipeline_mode == "kg_rag":
            # 安全预警 (隐去 cwe_id，加入防御契约)
            if res.graph_warnings:
                warning_lines = []
                for i, w in enumerate(res.graph_warnings, 1):
                    clean_warn = sanitize_cwe_text(w.warning)
                    clean_contract = sanitize_cwe_text(w.verification_contract)
                    contract_str = f"\n     * Verification Contract (Defense Requirements): {clean_contract}" if clean_contract else ""
                    warning_lines.append(f"  {i}. [{w.entity}]: {clean_warn}{contract_str}")
                section_warnings = "## Knowledge Graph Security Warnings\nThe following security warnings related to this code were retrieved from the Oil & Gas Industrial Knowledge Graph:\n" + "\n".join(warning_lines) + "\n"
            else:
                section_warnings = "## Knowledge Graph Security Warnings\nNo direct security warnings related to this code were retrieved from the Knowledge Graph.\n"
            section_code = f"## C/C++ Source Code for Audit\n```cpp\n{clean_code}\n```\n"
            assembled_prompt = f"{section_warnings}\n{section_code}"
        else:
            # base_llm 模式
            assembled_prompt = f"## C/C++ Source Code for Audit\n```cpp\n{clean_code}\n```\n"

        res.assembled_prompt_preview = assembled_prompt[:500]

        system_prompt = DIAGNOSIS_SYSTEM_5A if pipeline_mode == "kg_rag" else DIAGNOSIS_SYSTEM_5A_BASE_LLM
        conv = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Please objectively analyze whether the following code is safe or vulnerable, and output the result in pure JSON format:\n\n{assembled_prompt}"}
        ]
        conversations_5a.append(conv)
        valid_samples_5a.append(s)

    # 批量调用 Step 5a
    outputs_5a = llm.chat(
        conversations_5a,
        sampling_params=sampling_params_json,
        use_tqdm=True
    )

    # 存储 5a 结果并挑选出判断为 Vulnerable 的样本用于 5b
    vulnerable_samples_info = []
    binary_results_map = {}

    for idx, out in enumerate(outputs_5a):
        s = valid_samples_5a[idx]
        sid = s.sample_id
        res_text = out.outputs[0].text
        try:
            binary_res = parse_json_output(res_text, BinaryDiagnosis)
            binary_results_map[sid] = binary_res
            if binary_res.is_vulnerable:
                vulnerable_samples_info.append(s)
        except Exception as e:
            logger.error(f"样本 {sid} Step 5a 解析异常: {e}，将启用关键词正则兜底")
            # 尝试从推理文本中进行兜底匹配
            text_lower = res_text.lower()
            is_vuln = False
            if '"is_vulnerable": true' in text_lower or 'vulnerable' in text_lower or 'vulnerability' in text_lower:
                # 排除 "is_vulnerable": false 的干扰
                if '"is_vulnerable": false' not in text_lower and 'not vulnerable' not in text_lower:
                    is_vuln = True
            
            logger.info(f"[5a FALLBACK] 样本 {sid} 判定结果为: {is_vuln}")
            binary_res = BinaryDiagnosis(
                graph_warning_critique="Fallback: Model response was not valid JSON, unable to perform critique.",
                code_logic_analysis="Fallback: Model response was not valid JSON, unable to perform code logic analysis.",
                is_vulnerable=is_vuln,
                confidence=0.5
            )
            binary_results_map[sid] = binary_res
            if is_vuln:
                vulnerable_samples_info.append(s)

    # ============================================================
    # 阶段四：Step 5b CWE 类别定位（仅针对 5a 判为漏洞的样本）
    # ============================================================
    cwe_results_map = {}
    if vulnerable_samples_info:
        logger.info(f"[STAGE 4/5] 批量定位漏洞 CWE (Step 5b)，包含疑似漏洞样本: {len(vulnerable_samples_info)} 个 ...")
        conversations_5b = []
        for s in vulnerable_samples_info:
            res = results_dict[s.sample_id]
            # 这里的 assembled_prompt 前缀与 5a 保持高度一致（为了最大化命中 Prefix Caching 缓存）
            clean_code = s.code.strip().replace("\r\n", "\n")
            if pipeline_mode == "kg_rag":
                if res.graph_warnings:
                    warning_lines = []
                    for i, w in enumerate(res.graph_warnings, 1):
                        clean_warn = sanitize_cwe_text(w.warning)
                        clean_contract = sanitize_cwe_text(w.verification_contract)
                        contract_str = f"\n     * Verification Contract (Defense Requirements): {clean_contract}" if clean_contract else ""
                        warning_lines.append(f"  {i}. [{w.entity}]: {clean_warn}{contract_str}")
                    section_warnings = "## Knowledge Graph Security Warnings\nThe following security warnings related to this code were retrieved from the Oil & Gas Industrial Knowledge Graph:\n" + "\n".join(warning_lines) + "\n"
                else:
                    section_warnings = "## Knowledge Graph Security Warnings\nNo direct security warnings related to this code were retrieved from the Knowledge Graph.\n"
                section_code = f"## C/C++ Source Code for Audit\n```cpp\n{clean_code}\n```\n"
                assembled_prompt = f"{section_warnings}\n{section_code}"
            else:
                assembled_prompt = f"## C/C++ Source Code for Audit\n```cpp\n{clean_code}\n```\n"

            # 收集候选 CWE 池
            cwe_candidates_set = set()
            if pipeline_mode == "kg_rag":
                if res.extraction and res.extraction.context_possible_cwes:
                    for cwe in res.extraction.context_possible_cwes:
                        cwe_clean = cwe.strip().upper().replace('_', '-')
                        if cwe_clean.startswith("CWE-") or re.match(r'^CWE-\d+$', cwe_clean):
                            cwe_candidates_set.add(cwe_clean)
                        else:
                            digits = re.search(r'\d+', cwe_clean)
                            if digits:
                                cwe_candidates_set.add(f"CWE-{digits.group(0)}")
                if res.graph_warnings:
                    for w in res.graph_warnings:
                        if w.cwe_id:
                            cwe_clean = w.cwe_id.strip().upper().replace('_', '-')
                            if cwe_clean.startswith("CWE-") or re.match(r'^CWE-\d+$', cwe_clean):
                                cwe_candidates_set.add(cwe_clean)
                            else:
                                digits = re.search(r'\d+', cwe_clean)
                                if digits:
                                    cwe_candidates_set.add(f"CWE-{digits.group(0)}")
            
            if cwe_candidates_set:
                cwe_candidates = ", ".join(sorted(list(cwe_candidates_set)))
            else:
                cwe_candidates = "No recommended candidates"

            system_prompt_5b = DIAGNOSIS_SYSTEM_5B.format(cwe_candidates=cwe_candidates)

            conv = [
                {"role": "system", "content": system_prompt_5b},
                {"role": "user", "content": f"Analyze the following vulnerable code and identify its ROOT CAUSE CWE ID. Output pure JSON:\n\n{assembled_prompt}"}
            ]
            conversations_5b.append(conv)

        # 批量调用 Step 5b
        outputs_5b = llm.chat(
            conversations_5b,
            sampling_params=sampling_params_json,
            use_tqdm=True
        )

        for idx, out in enumerate(outputs_5b):
            sid = vulnerable_samples_info[idx].sample_id
            res_text = out.outputs[0].text
            try:
                cwe_res = parse_json_output(res_text, CWEDiagnosis)
                cwe_results_map[sid] = cwe_res
            except Exception as e:
                logger.error(f"样本 {sid} Step 5b 解析异常: {e}，将启用 CWE 正则兜底")
                # 正则匹配形如 CWE-787, CWE_787, CWE787, cwe-121 等标识
                cwe_match = re.search(r"cwe[-_]?\d+", res_text, re.IGNORECASE)
                if cwe_match:
                    raw_cwe = cwe_match.group(0).upper()
                    # 格式化为标准 CWE-XXX 格式
                    cwe_num_match = re.search(r"\d+", raw_cwe)
                    cwe_id = f"CWE-{cwe_num_match.group(0)}" if cwe_num_match else raw_cwe
                    logger.info(f"[5b FALLBACK] 样本 {sid} 正则提取到 CWE: {cwe_id}")
                    cwe_results_map[sid] = CWEDiagnosis(cwe_id=cwe_id, vulnerability_type="正则兜底提取")
                else:
                    results_dict[sid].status = "error"
                    results_dict[sid].error_message = f"Step 5b JSON parse error: {e}"

    # ============================================================
    # 阶段五：Step 5c 诊断报告生成（所有无错样本均进行，Safe 给出一条说明，Vulnerable 抽取行号）
    # ============================================================
    logger.info(f"[STAGE 5/5] 批量生成漏洞分析报告与受影响行提取 (Step 5c) ...")
    conversations_5c = []
    valid_samples_5c = []

    for s in pending_samples:
        res = results_dict[s.sample_id]
        if res.status == "error" or s.sample_id not in binary_results_map:
            continue

        binary_res = binary_results_map[s.sample_id]
        clean_code = s.code.strip().replace("\r\n", "\n")
        
        # 保持与 5a / 5b 前缀一致
        if pipeline_mode == "kg_rag":
            if res.graph_warnings:
                warning_lines = []
                for i, w in enumerate(res.graph_warnings, 1):
                    clean_warn = sanitize_cwe_text(w.warning)
                    clean_contract = sanitize_cwe_text(w.verification_contract)
                    contract_str = f"\n     * Verification Contract (Defense Requirements): {clean_contract}" if clean_contract else ""
                    warning_lines.append(f"  {i}. [{w.entity}]: {clean_warn}{contract_str}")
                section_warnings = "## Knowledge Graph Security Warnings\nThe following security warnings related to this code were retrieved from the Oil & Gas Industrial Knowledge Graph:\n" + "\n".join(warning_lines) + "\n"
            else:
                section_warnings = "## Knowledge Graph Security Warnings\nNo direct security warnings related to this code were retrieved from the Knowledge Graph.\n"
            section_code = f"## C/C++ Source Code for Audit\n```cpp\n{clean_code}\n```\n"
            assembled_prompt = f"{section_warnings}\n{section_code}"
        else:
            assembled_prompt = f"## C/C++ Source Code for Audit\n```cpp\n{clean_code}\n```\n"

        status_str = "VULNERABLE" if binary_res.is_vulnerable else "SAFE"
        cwe_info = "None"
        if binary_res.is_vulnerable and s.sample_id in cwe_results_map:
            cwe_info = f"{cwe_results_map[s.sample_id].cwe_id} ({cwe_results_map[s.sample_id].vulnerability_type})"

        conv = [
            {"role": "system", "content": DIAGNOSIS_SYSTEM_5C},
            {"role": "user", "content": (
                f"Context:\n{assembled_prompt}\n\n"
                f"This code has been classified as: {status_str}.\n"
                f"If vulnerable, the identified root cause is: {cwe_info}.\n"
                "Please extract affected lines and provide a concise Chinese explanation in pure JSON format."
            )}
        ]
        conversations_5c.append(conv)
        valid_samples_5c.append(s)

    # 批量调用 Step 5c
    outputs_5c = llm.chat(
        conversations_5c,
        sampling_params=sampling_params_report,
        use_tqdm=True
    )

    for idx, out in enumerate(outputs_5c):
        s = valid_samples_5c[idx]
        sid = s.sample_id
        res_text = out.outputs[0].text
        try:
            report_res = parse_json_output(res_text, ReportDiagnosis)
            binary_res = binary_results_map[sid]
            cwe_res = cwe_results_map.get(sid, None)

            # 汇总为完整的 DiagnosisResult
            diagnosis = DiagnosisResult(
                graph_warning_critique=binary_res.graph_warning_critique,
                code_logic_analysis=binary_res.code_logic_analysis,
                is_vulnerable=binary_res.is_vulnerable,
                confidence=binary_res.confidence,
                cwe_id=cwe_res.cwe_id if cwe_res else "",
                vulnerability_type=cwe_res.vulnerability_type if cwe_res else "",
                explanation=report_res.explanation,
                affected_lines=report_res.affected_lines,
            )
            results_dict[sid].diagnosis = diagnosis
            results_dict[sid].status = "success"
        except Exception as e:
            logger.error(f"样本 {sid} Step 5c 解析异常: {e}，将启用文本兜底")
            binary_res = binary_results_map[sid]
            cwe_res = cwe_results_map.get(sid, None)
            
            # 剥离 think 标签后，将所有大模型输出直接作为 explanation 字段
            clean_text = re.sub(r"<think>.*?</think>", "", res_text, flags=re.DOTALL).strip()
            if not clean_text:
                clean_text = "诊断生成异常，请查看后台完整推理日志。"
                
            diagnosis = DiagnosisResult(
                graph_warning_critique=binary_res.graph_warning_critique,
                code_logic_analysis=binary_res.code_logic_analysis,
                is_vulnerable=binary_res.is_vulnerable,
                confidence=binary_res.confidence,
                cwe_id=cwe_res.cwe_id if cwe_res else "",
                vulnerability_type=cwe_res.vulnerability_type if cwe_res else "",
                explanation=clean_text[:1000],  # 截断部分过长输出
                affected_lines=[],
            )
            results_dict[sid].diagnosis = diagnosis
            results_dict[sid].status = "success"

    # ============================================================
    # 保存结果并清理资源
    # ============================================================
    if neo4j_driver:
        neo4j_driver.close()
        logger.info("Neo4j 连接已关闭")

    # 汇总并保存所有结果 (包括之前的成功结果和新产生的结果)
    final_results = {}
    for sid, old_res in successful_results.items():
        final_results[sid] = old_res
    for sid, new_res in results_dict.items():
        final_results[sid] = new_res

    # 保存为格式化的 JSON 数组列表
    logger.info(f"正在保存检测结果到: {result_file} ...")
    output_records = []
    for s in samples:
        if s.sample_id in final_results:
            output_records.append(json.loads(final_results[s.sample_id].model_dump_json()))
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(output_records, f, ensure_ascii=False, indent=2)

    total_time = time.time() - start_total_time
    logger.info(
        f"\n{'='*60}\n"
        f"[COMPLETED] 离线批量检测完成!\n"
        f"  总样本数: {len(samples)}\n"
        f"  本次实际检测样本数: {len(pending_samples)}\n"
        f"  运行时间: {total_time:.2f} 秒\n"
        f"  平均单样本耗时: {total_time/max(1, len(pending_samples)):.2f} 秒\n"
        f"  结果文件: {result_file}\n"
        f"{'='*60}"
    )


if __name__ == "__main__":
    main()
