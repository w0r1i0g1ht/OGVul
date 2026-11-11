# -*- coding: utf-8 -*-
"""
evaluate.py — 检测结果评估与指标计算
油气工业软件漏洞检测系统 KG-RAG Pipeline

功能:
  - 从 detection_results.jsonl 加载检测结果
  - 计算二分类指标: Precision, Recall, F1, Accuracy
  - 计算 CWE 命中率（预测的 CWE 是否包含真实 CWE）
  - 按来源类型 / CWE 类别 / Pipeline 模式 分组统计
  - 生成结构化的评估报告（Markdown + JSON）

用法:
  python evaluate.py                     # 使用默认路径
  python evaluate.py --config my.yaml    # 使用自定义配置
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("evaluate")


# ============================================================
# 指标计算工具
# ============================================================


def compute_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    """
    根据混淆矩阵的四个值计算常用二分类指标。

    Returns:
        包含 precision, recall, f1, accuracy, tp, fp, fn, tn, total 的字典
    """
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "total": total,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


# ============================================================
# 结果加载与解析
# ============================================================


def load_results(jsonl_path: Path) -> list[dict]:
    """从 JSON 或 JSONL 文件加载检测结果。"""
    target_path = jsonl_path
    
    # 优先检测直接指定的路径是否存在
    if not target_path.exists():
        # 如果不存在，尝试自动修正/切换后缀以匹配存在的对应文件
        for ext in [".json", ".jsonl"]:
            test_path = target_path.with_suffix(ext)
            if test_path.exists():
                target_path = test_path
                break

    if not target_path.exists():
        logger.error(f"结果文件不存在: {target_path}")
        return []

    records = []
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            if content.startswith("["):
                records = json.loads(content)
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.warning(f"JSONL行解析失败: {e}")
    except Exception as e:
        logger.error(f"读取文件失败: {e}")

    logger.info(f"加载 {len(records)} 条检测结果: {target_path}")
    return records


def normalize_cwe_id(cwe_str: str) -> str:
    """标准化 CWE ID 格式，如 'cwe-119' -> 'CWE-119'"""
    if not cwe_str:
        return ""
    cwe_str = cwe_str.upper().strip()
    if cwe_str.startswith("CWE-"):
        return cwe_str
    if cwe_str.isdigit():
        return f"CWE-{cwe_str}"
    return cwe_str


def build_cwe_hierarchy(csv_path: Path) -> dict:
    """从 1000.csv 解析 CWE 层级结构，建立基于 VIEW 1000 的 parent 映射"""
    cwe_dict = {}
    if not csv_path.exists():
        logger.warning(f"CWE 层级文件不存在: {csv_path}，层级指标计算将退化为精确匹配。")
        return cwe_dict

    try:
        with open(csv_path, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cwe_id_raw = row.get('CWE-ID')
                if not cwe_id_raw:
                    continue
                cwe_id = f"CWE-{cwe_id_raw.strip()}"
                
                related_str = row.get('Related Weaknesses', '')
                parents = []
                if related_str:
                    entries = [e for e in related_str.split('::') if e.strip()]
                    for entry in entries:
                        if 'NATURE:ChildOf' in entry and 'VIEW ID:1000' in entry:
                            id_match = re.search(r'CWE ID:(\d+)', entry)
                            if id_match:
                                parents.append(f"CWE-{id_match.group(1)}")
                
                cwe_dict[cwe_id] = {
                    "name": row.get('Name', ''),
                    "abstraction": row.get('Weakness Abstraction', ''),
                    "parents": parents
                }
    except Exception as e:
        logger.error(f"解析 {csv_path} 层级树失败: {e}")

    return cwe_dict


def find_path_to_pillar(cwe_id: str, cwe_dict: dict) -> list[str]:
    """自底向上寻找通往 Pillar (如 CWE-664 等顶层支柱节点) 的路径"""
    cwe_id = normalize_cwe_id(cwe_id)
    if not cwe_id or cwe_id not in cwe_dict:
        return [cwe_id] if cwe_id else []

    # BFS 寻找最短路径
    queue = deque([[cwe_id]])
    visited = {cwe_id}

    while queue:
        path = queue.popleft()
        curr = path[-1]

        info = cwe_dict.get(curr)
        if not info:
            continue

        if info.get("abstraction") == "Pillar":
            return list(reversed(path))

        for parent in info.get("parents", []):
            if parent not in visited:
                visited.add(parent)
                queue.append(path + [parent])

    # 如果无法到达 Pillar，寻找最长向上路径的 root
    queue = deque([[cwe_id]])
    longest_path = [cwe_id]
    while queue:
        path = queue.popleft()
        curr = path[-1]
        info = cwe_dict.get(curr)
        if info and info.get("parents"):
            for parent in info["parents"]:
                new_path = path + [parent]
                queue.append(new_path)
                if len(new_path) > len(longest_path):
                    longest_path = new_path
        else:
            if len(path) > len(longest_path):
                longest_path = path

    return list(reversed(longest_path))


def get_expanded_path(cwe_id: str, cwe_dict: dict) -> list[str]:
    """将路径补齐或截断为 5 层的路径向量"""
    path = find_path_to_pillar(cwe_id, cwe_dict)
    if not path:
        return [cwe_id] * 5 if cwe_id else [""] * 5

    if len(path) < 5:
        leaf = path[-1]
        path = path + [leaf] * (5 - len(path))
    elif len(path) > 5:
        path = path[:4] + [path[-1]]
    return path


def compute_h_score(pred_cwe: str, gt_cwe: str, cwe_dict: dict) -> float:
    """计算预测 CWE 与真实 CWE 的重合层级 H-Score = k/5"""
    pred_cwe = normalize_cwe_id(pred_cwe)
    gt_cwe = normalize_cwe_id(gt_cwe)

    if not pred_cwe or not gt_cwe:
        return 0.0

    if pred_cwe == gt_cwe:
        return 1.0

    if not cwe_dict:
        return 0.0

    path_pred = get_expanded_path(pred_cwe, cwe_dict)
    path_true = get_expanded_path(gt_cwe, cwe_dict)

    k = 0
    for p, t in zip(path_pred, path_true):
        if p == t and p != "":
            k += 1
        else:
            break
    return k / 5.0


def classify_record(record: dict) -> tuple[str, str, str, str]:
    """
    从单条记录中提取分类信息与 CWE ID。

    Returns:
        (predicted_label, ground_truth_label, predicted_cwe, ground_truth_cwe)
        - predicted_label: "vulnerable" / "safe" / "error"
        - ground_truth_label: "vulnerable" / "safe"
    """
    gt_label = record.get("ground_truth_label", "")
    gt_cwe = normalize_cwe_id(record.get("ground_truth_cwe", ""))
    status = record.get("status", "error")
    diagnosis = record.get("diagnosis")

    # 处理失败的样本
    if status == "error" or diagnosis is None:
        return "error", gt_label, "", gt_cwe

    is_vuln = diagnosis.get("is_vulnerable", False)
    pred_label = "vulnerable" if is_vuln else "safe"
    pred_cwe = normalize_cwe_id(diagnosis.get("cwe_id", ""))

    return pred_label, gt_label, pred_cwe, gt_cwe


# ============================================================
# 分组评估
# ============================================================


def evaluate_group(records: list[dict], cwe_dict: dict | None = None, group_name: str = "Overall") -> dict:
    """
    对一组记录计算评估指标，包括二分类指标、严格匹配命中率、以及仅对 TP 计算的层级匹配命中率。
    同时计算图谱预警相关的指标：预警覆盖率、预警命中率、预警层级命中率。
    """
    tp = fp = fn = tn = 0
    error_count = 0
    cwe_hit_count = 0
    cwe_total = 0  # 有真实 CWE 标注且预测为 vulnerable 的样本数 (TP)
    cwe_h_hit_sum = 0.0  # 层级匹配分之和

    # 预警相关指标计数器
    warn_covered_samples = 0
    warn_total_count = 0
    warn_hit_count = 0
    warn_h_hit_sum = 0.0

    for record in records:
        pred, gt, pred_cwe, gt_cwe = classify_record(record)

        if pred == "error":
            error_count += 1
            continue

        # 统计预警覆盖率（只要有图谱预警，就算覆盖）
        warnings = record.get("graph_warnings", [])
        if warnings:
            warn_covered_samples += 1

        # 只对真漏洞（gt == "vulnerable"）且标注了真实 CWE 的情况统计预警的精准度
        if gt == "vulnerable" and gt_cwe:
            # 兼容可能的多个 CWE，如 "CWE-120,CWE-121"
            gt_cwes = set()
            import re
            matches = re.findall(r'(?i)cwe[-_]?\d+', gt_cwe)
            for m in matches:
                digits = re.search(r'\d+', m)
                if digits:
                    gt_cwes.add(f"CWE-{digits.group(0)}")

            for w in warnings:
                warn_total_count += 1
                w_cwe_raw = w.get("cwe_id", "")
                w_cwe = normalize_cwe_id(w_cwe_raw)
                
                # 预警严格命中
                if w_cwe in gt_cwes:
                    warn_hit_count += 1
                
                # 预警层级匹配：计算 w_cwe 与 gt_cwe 中的层级匹配度分数
                max_score = 0.0
                for g_cwe in gt_cwes:
                    score = compute_h_score(w_cwe, g_cwe, cwe_dict)
                    if score > max_score:
                        max_score = score
                warn_h_hit_sum += max_score

        if gt == "vulnerable" and pred == "vulnerable":
            tp += 1
            if gt_cwe:
                cwe_total += 1
                if pred_cwe == gt_cwe:
                    cwe_hit_count += 1
                # 计算层级 H-Score
                score = compute_h_score(pred_cwe, gt_cwe, cwe_dict)
                cwe_h_hit_sum += score
        elif gt == "safe" and pred == "vulnerable":
            fp += 1
        elif gt == "vulnerable" and pred == "safe":
            fn += 1
        elif gt == "safe" and pred == "safe":
            tn += 1

    metrics = compute_metrics(tp, fp, fn, tn)

    metrics["group"] = group_name
    metrics["error_count"] = error_count
    metrics["cwe_hit_count"] = cwe_hit_count
    metrics["cwe_total"] = cwe_total
    metrics["cwe_hit_rate"] = (
        round(cwe_hit_count / cwe_total, 4) if cwe_total > 0 else 0.0
    )
    
    # 层级匹配命中率（只在 TP 集合上计算）
    metrics["cwe_h_hit_rate"] = (
        round(cwe_h_hit_sum / cwe_total, 4) if cwe_total > 0 else 0.0
    )

    # 写入预警统计指标
    metrics["warn_coverage_rate"] = (
        round(warn_covered_samples / len(records), 4) if records else 0.0
    )
    metrics["warn_hit_rate"] = (
        round(warn_hit_count / warn_total_count, 4) if warn_total_count > 0 else 0.0
    )
    metrics["warn_h_hit_rate"] = (
        round(warn_h_hit_sum / warn_total_count, 4) if warn_total_count > 0 else 0.0
    )
    metrics["warn_covered_samples"] = warn_covered_samples
    metrics["warn_total_count"] = warn_total_count
    metrics["warn_hit_count"] = warn_hit_count

    return metrics


def evaluate_all(records: list[dict], cwe_dict: dict | None = None) -> dict:
    """
    执行全面评估，按多个维度分组计算指标。

    返回结构化的评估报告字典。
    """
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_records": len(records),
    }

    # ---------- 按 pipeline_mode 分组 ----------
    mode_groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        mode_groups[r.get("pipeline_mode", "unknown")].append(r)

    report["by_pipeline_mode"] = {}
    for mode, group_records in sorted(mode_groups.items()):
        report["by_pipeline_mode"][mode] = evaluate_group(
            group_records, cwe_dict, f"mode:{mode}"
        )

    # ---------- 按来源类型分组 ----------
    source_groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        source_groups[r.get("source_type", "unknown")].append(r)

    report["by_source_type"] = {}
    for src, group_records in sorted(source_groups.items()):
        report["by_source_type"][src] = evaluate_group(
            group_records, cwe_dict, f"source:{src}"
        )

    # ---------- 按 CWE 分组 ----------
    cwe_groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        cwe = r.get("ground_truth_cwe", "") or "unknown"
        cwe_groups[cwe].append(r)

    report["by_cwe"] = {}
    for cwe, group_records in sorted(cwe_groups.items()):
        report["by_cwe"][cwe] = evaluate_group(
            group_records, cwe_dict, f"cwe:{cwe}"
        )

    # ---------- 按 pipeline_mode + source_type 联合分组 ----------
    combined_groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        key = f"{r.get('pipeline_mode', 'unknown')}|{r.get('source_type', 'unknown')}"
        combined_groups[key].append(r)

    report["by_mode_and_source"] = {}
    for key, group_records in sorted(combined_groups.items()):
        report["by_mode_and_source"][key] = evaluate_group(
            group_records, cwe_dict, key
        )

    # ---------- 全局汇总 ----------
    report["overall"] = evaluate_group(records, cwe_dict, "Overall")

    return report


# ============================================================
# 报告生成
# ============================================================


def format_metrics_table(
    metrics_dict: dict[str, dict], title: str
) -> str:
    """将一组指标格式化为 Markdown 表格。"""
    lines = [
        f"### {title}\n",
        "| 分组 | 样本数 | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy | CWE命中率(严格) | CWE命中率(层级) | 错误数 | 预警覆盖率 | 预警命中率 | 预警层级命中率 |",
        "|------|--------|----|----|----|----|-----------|--------|-----|----------|-----------------|-----------------|--------|------------|------------|----------------|",
    ]

    for key, m in metrics_dict.items():
        lines.append(
            f"| {key} | {m['total']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
            f"{m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['accuracy']:.4f} | "
            f"{m['cwe_hit_rate']:.4f} ({m['cwe_hit_count']}/{m['cwe_total']}) | "
            f"{m['cwe_h_hit_rate']:.4f} | {m['error_count']} | "
            f"{m.get('warn_coverage_rate', 0.0):.4f} ({m.get('warn_covered_samples', 0)}/{m['total']}) | "
            f"{m.get('warn_hit_rate', 0.0):.4f} ({m.get('warn_hit_count', 0)}/{m.get('warn_total_count', 0)}) | "
            f"{m.get('warn_h_hit_rate', 0.0):.4f} |"
        )

    return "\n".join(lines)


def generate_markdown_report(report: dict) -> str:
    """将评估报告生成为 Markdown 格式。"""
    sections = []

    # 标题
    sections.append("# 🛡️ 漏洞检测评估报告\n")
    sections.append(f"> 生成时间: {report['generated_at']}")
    sections.append(f"> 总样本数: {report['total_records']}\n")
    sections.append("---\n")

    # 全局汇总
    overall = report["overall"]
    sections.append("## 📊 全局指标汇总\n")
    sections.append(f"| 指标 | 值 |")
    sections.append(f"|------|-----|")
    sections.append(f"| **Accuracy** | {overall['accuracy']:.4f} |")
    sections.append(f"| **Precision** | {overall['precision']:.4f} |")
    sections.append(f"| **Recall** | {overall['recall']:.4f} |")
    sections.append(f"| **F1-Score** | {overall['f1']:.4f} |")
    sections.append(
        f"| **CWE 命中率 (严格)** | {overall['cwe_hit_rate']:.4f} "
        f"({overall['cwe_hit_count']}/{overall['cwe_total']}) |"
    )
    sections.append(
        f"| **CWE 命中率 (层级 H-Score)** | {overall['cwe_h_hit_rate']:.4f} |"
    )
    sections.append(f"| TP / FP / FN / TN | {overall['tp']} / {overall['fp']} / {overall['fn']} / {overall['tn']} |")
    sections.append(f"| 错误样本 | {overall['error_count']} |")
    sections.append(
        f"| **预警覆盖率** | {overall.get('warn_coverage_rate', 0.0):.4f} "
        f"({overall.get('warn_covered_samples', 0)}/{overall['total']}) |"
    )
    sections.append(
        f"| **预警命中率 (严格)** | {overall.get('warn_hit_rate', 0.0):.4f} "
        f"({overall.get('warn_hit_count', 0)}/{overall.get('warn_total_count', 0)}) |"
    )
    sections.append(
        f"| **预警层级命中率** | {overall.get('warn_h_hit_rate', 0.0):.4f} |\n"
    )
    sections.append("---\n")

    # 按 Pipeline 模式
    sections.append(
        format_metrics_table(
            report["by_pipeline_mode"],
            "🔬 按 Pipeline 模式",
        )
    )
    sections.append("\n---\n")

    # 按来源类型
    sections.append(
        format_metrics_table(
            report["by_source_type"],
            "📁 按样本来源类型",
        )
    )
    sections.append("\n---\n")

    # 按 CWE
    sections.append(
        format_metrics_table(
            report["by_cwe"],
            "🔖 按 CWE 漏洞类别",
        )
    )
    sections.append("\n---\n")

    # 按模式+来源联合分组
    sections.append(
        format_metrics_table(
            report["by_mode_and_source"],
            "🧪 按模式 × 来源类型（交叉分析）",
        )
    )

    return "\n".join(sections)


# ============================================================
# 主入口
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description="漏洞检测结果评估 — 计算 Precision / Recall / F1 / CWE 命中率 / 层级拓扑匹配度",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="配置文件路径（默认: config.yaml）",
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="直接指定 JSONL 结果文件路径（优先级高于 config）",
    )
    args = parser.parse_args()

    # 确定结果文件路径
    if args.input:
        jsonl_path = Path(args.input)
    else:
        config_path = Path(__file__).parent / args.config
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        output_dir = config["paths"]["output_dir"]
        result_file = config["runtime"]["result_file"]
        pipeline_mode = config["experiment"]["pipeline_mode"]
        
        # 按照 pipeline_mode 动态定位文件名
        if result_file.endswith(".jsonl"):
            base_name = result_file[:-6]
            result_filename = f"{base_name}_{pipeline_mode}.jsonl"
        elif result_file.endswith(".json"):
            base_name = result_file[:-5]
            result_filename = f"{base_name}_{pipeline_mode}.json"
        else:
            result_filename = f"{result_file}_{pipeline_mode}"
            
        output_roots = [Path(output_dir), Path(__file__).parent / "results"]
        output_roots = list(dict.fromkeys(output_roots))
        candidate_paths = []
        for output_path in output_roots:
            candidate_paths.append(output_path / result_file)
            candidate_paths.append(output_path / f"detection_results_agent_{pipeline_mode}.json")
            candidate_paths.append(output_path / result_filename)

        jsonl_path = candidate_paths[0]
        for candidate_path in candidate_paths:
            if candidate_path.exists():
                logger.info(f"自动选择结果文件: {candidate_path}")
                jsonl_path = candidate_path
                break

    # 加载 CWE 树状拓扑图
    csv_path = Path(__file__).parent / "1000.csv"
    logger.info(f"正在加载 CWE 树状拓扑: {csv_path}...")
    cwe_dict = build_cwe_hierarchy(csv_path)
    if cwe_dict:
        logger.info(f"CWE 树加载成功，共 {len(cwe_dict)} 个节点。")
    else:
        logger.warning("CWE 树加载为空，将关闭层级匹配分析。")

    # 加载结果
    records = load_results(jsonl_path)
    if not records:
        logger.error("无检测结果可评估")
        return

    # 过滤掉 status=error 仍参与统计（作为 error_count 单独计数）
    logger.info(f"有效记录: {len(records)} 条")

    # 执行评估
    report = evaluate_all(records, cwe_dict)

    # 输出目录
    output_dir = jsonl_path.parent
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 提取评估记录中的模式名称以用于报告命名
    record_mode = "unknown"
    if records:
        record_mode = records[0].get("pipeline_mode", "unknown")

    # 保存 JSON 报告
    json_path = output_dir / f"evaluation_report_{record_mode}_{timestamp}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    logger.info(f"JSON 报告已保存: {json_path}")

    # 保存 Markdown 报告
    md_content = generate_markdown_report(report)
    md_path = output_dir / f"evaluation_report_{record_mode}_{timestamp}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    logger.info(f"Markdown 报告已保存: {md_path}")

    # 控制台输出关键指标
    print("\n" + "=" * 60)
    print("评估结果摘要")
    print("=" * 60)

    overall = report["overall"]
    print(f"  总样本数:   {overall['total']} (+ {overall['error_count']} 错误)")
    print(f"  Accuracy:   {overall['accuracy']:.4f}")
    print(f"  Precision:  {overall['precision']:.4f}")
    print(f"  Recall:     {overall['recall']:.4f}")
    print(f"  F1-Score:   {overall['f1']:.4f}")
    print(
        f"  CWE 命中率(严格): {overall['cwe_hit_rate']:.4f} "
        f"({overall['cwe_hit_count']}/{overall['cwe_total']})"
    )
    print(f"  CWE 命中率(层级): {overall['cwe_h_hit_rate']:.4f}")
    print(f"  预警覆盖率: {overall.get('warn_coverage_rate', 0.0):.4f} ({overall.get('warn_covered_samples', 0)}/{overall['total']})")
    print(f"  预警命中率: {overall.get('warn_hit_rate', 0.0):.4f} ({overall.get('warn_hit_count', 0)}/{overall.get('warn_total_count', 0)})")
    print(f"  预警层级率: {overall.get('warn_h_hit_rate', 0.0):.4f}")
    print(f"  混淆矩阵:   TP={overall['tp']} FP={overall['fp']} "
          f"FN={overall['fn']} TN={overall['tn']}")

    # 如果有多个模式，输出对比
    if len(report["by_pipeline_mode"]) > 1:
        print(f"\n{'-' * 60}")
        print("Pipeline 模式对比")
        print(f"{'-' * 60}")
        print(f"  {'模式':<12} {'Precision':>10} {'Recall':>10} {'F1':>10} {'CWE命中率':>10} {'H-F1':>10}")
        for mode, m in report["by_pipeline_mode"].items():
            print(
                f"  {mode:<12} {m['precision']:>10.4f} {m['recall']:>10.4f} "
                f"{m['f1']:>10.4f} {m['cwe_hit_rate']:>10.4f} {m['h_f1']:>10.4f}"
            )

    print("=" * 60)
    print(f"\n完整报告: {md_path}")


if __name__ == "__main__":
    main()
