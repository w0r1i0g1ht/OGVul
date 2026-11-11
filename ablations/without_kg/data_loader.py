# -*- coding: utf-8 -*-
"""
data_loader.py — 统一样本数据加载器
油气工业软件漏洞检测系统 KG-RAG Pipeline

支持 4 种样本格式：
  1. CVE 真实漏洞  — CVEs/CVE-XXXX-XXXXX/vuln_code.md (Markdown 内嵌代码)
  2. CVE 修复样本  — CVEs/CVE-XXXX-XXXXX-fixed/vuln_code.md
  3. 合成漏洞样本  — output/Sample_CWEXXX_NNN/mutated_code.cpp (纯 C++ 代码)
  4. 合成安全样本  — output/Sample_CWEXXX_NNN/safe_code.cpp
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from schemas import SampleInfo

logger = logging.getLogger(__name__)


class DataLoader:
    """统一的漏洞样本加载器，路径从配置文件读取。"""

    def __init__(self, cve_dir: str, synthetic_dir: str):
        """
        Args:
            cve_dir: CVE 样本根目录路径
            synthetic_dir: 合成样本根目录路径
        """
        self.cve_dir = Path(cve_dir)
        self.synthetic_dir = Path(synthetic_dir)

    # ----------------------------------------------------------------
    # 公共接口
    # ----------------------------------------------------------------

    def load_all(self) -> list[SampleInfo]:
        """加载全部样本，返回统一格式的 SampleInfo 列表。"""
        samples: list[SampleInfo] = []

        samples.extend(self._load_cve_vuln())
        samples.extend(self._load_cve_fixed())
        samples.extend(self._load_synthetic_vuln())
        samples.extend(self._load_synthetic_safe())

        logger.info(
            f"数据加载完成: 共 {len(samples)} 个样本 "
            f"(CVE漏洞={len([s for s in samples if s.source_type == 'cve_vuln'])}, "
            f"CVE修复={len([s for s in samples if s.source_type == 'cve_fixed'])}, "
            f"合成漏洞={len([s for s in samples if s.source_type == 'synthetic_vuln'])}, "
            f"合成安全={len([s for s in samples if s.source_type == 'synthetic_safe'])})"
        )
        return samples

    # ----------------------------------------------------------------
    # CVE 真实漏洞样本
    # ----------------------------------------------------------------

    def _load_cve_vuln(self) -> list[SampleInfo]:
        """加载 CVE 真实漏洞样本（目录名不以 -fixed 结尾）。"""
        samples = []
        if not self.cve_dir.exists():
            logger.warning(f"CVE 目录不存在: {self.cve_dir}")
            return samples

        for d in sorted(self.cve_dir.iterdir()):
            if not d.is_dir():
                continue
            if not d.name.startswith("CVE-"):
                continue
            if d.name.endswith("-fixed"):
                continue

            code = self._extract_code_from_markdown(d / "vuln_code.md")
            if not code:
                logger.warning(f"无法提取代码: {d.name}/vuln_code.md")
                continue

            cwe_id = self._read_cwe_id(d / "vuln_info.json")
            samples.append(
                SampleInfo(
                    sample_id=d.name,
                    source_type="cve_vuln",
                    label="vulnerable",
                    code=code,
                    cwe_id=cwe_id,
                )
            )
        logger.info(f"CVE 漏洞样本加载: {len(samples)} 条")
        return samples

    # ----------------------------------------------------------------
    # CVE 修复样本
    # ----------------------------------------------------------------

    def _load_cve_fixed(self) -> list[SampleInfo]:
        """加载 CVE 修复样本（目录名以 -fixed 结尾）。"""
        samples = []
        if not self.cve_dir.exists():
            return samples

        for d in sorted(self.cve_dir.iterdir()):
            if not d.is_dir():
                continue
            if not d.name.endswith("-fixed"):
                continue

            code = self._extract_code_from_markdown(d / "vuln_code.md")
            if not code:
                logger.warning(f"无法提取代码: {d.name}/vuln_code.md")
                continue

            cwe_id = self._read_cwe_id(d / "vuln_info.json")
            samples.append(
                SampleInfo(
                    sample_id=d.name,
                    source_type="cve_fixed",
                    label="safe",
                    code=code,
                    cwe_id=cwe_id,
                )
            )
        logger.info(f"CVE 修复样本加载: {len(samples)} 条")
        return samples

    # ----------------------------------------------------------------
    # 合成漏洞样本
    # ----------------------------------------------------------------

    def _load_synthetic_vuln(self) -> list[SampleInfo]:
        """加载合成漏洞样本（mutated_code.cpp）。"""
        samples = []
        if not self.synthetic_dir.exists():
            logger.warning(f"合成样本目录不存在: {self.synthetic_dir}")
            return samples

        for d in sorted(self.synthetic_dir.iterdir()):
            if not d.is_dir():
                continue
            if not d.name.startswith("Sample_"):
                continue

            code_file = d / "mutated_code.cpp"
            if not code_file.exists():
                logger.warning(f"漏洞代码文件不存在: {code_file}")
                continue

            code = code_file.read_text(encoding="utf-8")
            if not code.strip():
                continue

            cwe_id = self._read_cwe_id(d / "vuln_info.json")
            samples.append(
                SampleInfo(
                    sample_id=f"{d.name}_vuln",
                    source_type="synthetic_vuln",
                    label="vulnerable",
                    code=code,
                    cwe_id=cwe_id,
                )
            )
        logger.info(f"合成漏洞样本加载: {len(samples)} 条")
        return samples

    # ----------------------------------------------------------------
    # 合成安全样本
    # ----------------------------------------------------------------

    def _load_synthetic_safe(self) -> list[SampleInfo]:
        """加载合成安全样本（safe_code.cpp）。"""
        samples = []
        if not self.synthetic_dir.exists():
            return samples

        for d in sorted(self.synthetic_dir.iterdir()):
            if not d.is_dir():
                continue
            if not d.name.startswith("Sample_"):
                continue

            code_file = d / "safe_code.cpp"
            if not code_file.exists():
                logger.warning(f"安全代码文件不存在: {code_file}")
                continue

            code = code_file.read_text(encoding="utf-8")
            if not code.strip():
                continue

            cwe_id = self._read_cwe_id(d / "vuln_info.json")
            samples.append(
                SampleInfo(
                    sample_id=f"{d.name}_safe",
                    source_type="synthetic_safe",
                    label="safe",
                    code=code,
                    cwe_id=cwe_id,
                )
            )
        logger.info(f"合成安全样本加载: {len(samples)} 条")
        return samples

    # ----------------------------------------------------------------
    # 工具方法
    # ----------------------------------------------------------------

    @staticmethod
    def _extract_code_from_markdown(md_path: Path) -> str:
        """
        从 Markdown 文件中提取 ```cpp ... ``` 代码块的内容。

        如果文件包含多个代码块，则全部拼接（以换行分隔）。
        """
        if not md_path.exists():
            return ""

        content = md_path.read_text(encoding="utf-8")
        # 匹配任意语言标识的代码块（```cpp, ```c, ```jsp, 或无标识的 ```）
        pattern = r"```[a-zA-Z+]*\s*\n(.*?)```"
        matches = re.findall(pattern, content, re.DOTALL)

        if not matches:
            return ""

        return "\n\n".join(match.strip() for match in matches)

    @staticmethod
    def _read_cwe_id(json_path: Path) -> str:
        """从 vuln_info.json 中读取 cwe_id 字段。"""
        if not json_path.exists():
            return ""

        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            return data.get("cwe_id", "")
        except (json.JSONDecodeError, KeyError):
            return ""
