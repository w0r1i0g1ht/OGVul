from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from agent_schemas import AgentDetectionResult
from schemas import BinaryDiagnosis, DiagnosisResult, DualExtraction, GraphWarning


class GlobalPerceptionCheckpoint(BaseModel):
    checkpoint_version: str
    sample_id: str
    extraction: DualExtraction
    global_graph_warnings: list[GraphWarning] = Field(default_factory=list)
    global_risk_assessment: BinaryDiagnosis
    global_preliminary_diagnosis: DiagnosisResult
    raw_extraction_output: str = ""
    raw_global_risk_output: str = ""
    raw_global_preliminary_output: str = ""

    @classmethod
    def from_result(
        cls,
        result: AgentDetectionResult,
        checkpoint_version: str,
    ) -> "GlobalPerceptionCheckpoint":
        if (
            result.extraction is None
            or result.global_risk_assessment is None
            or result.global_preliminary_diagnosis is None
        ):
            raise ValueError(f"Global perception is incomplete for {result.sample_id}")
        return cls(
            checkpoint_version=checkpoint_version,
            sample_id=result.sample_id,
            extraction=result.extraction,
            global_graph_warnings=[],
            global_risk_assessment=result.global_risk_assessment,
            global_preliminary_diagnosis=result.global_preliminary_diagnosis,
            raw_extraction_output=result.raw_extraction_output,
            raw_global_risk_output=result.raw_global_risk_output,
            raw_global_preliminary_output=result.raw_global_preliminary_output,
        )

    def restore_into(self, result: AgentDetectionResult) -> None:
        result.extraction = self.extraction.model_copy(deep=True)
        result.global_graph_warnings = []
        result.graph_warnings = []
        result.global_risk_assessment = self.global_risk_assessment.model_copy(deep=True)
        result.global_preliminary_diagnosis = self.global_preliminary_diagnosis.model_copy(deep=True)
        result.raw_extraction_output = self.raw_extraction_output
        result.raw_global_risk_output = self.raw_global_risk_output
        result.raw_global_preliminary_output = self.raw_global_preliminary_output


def load_global_checkpoints(
    path: Path,
    checkpoint_version: str,
) -> dict[str, GlobalPerceptionCheckpoint]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("checkpoint_version") != checkpoint_version:
            return {}
        checkpoints = {}
        for record in payload.get("records", []):
            checkpoint = GlobalPerceptionCheckpoint.model_validate(record)
            if checkpoint.checkpoint_version != checkpoint_version:
                return {}
            checkpoints[checkpoint.sample_id] = checkpoint
        return checkpoints
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def save_global_checkpoints(
    path: Path,
    checkpoints: dict[str, GlobalPerceptionCheckpoint],
) -> None:
    versions = {checkpoint.checkpoint_version for checkpoint in checkpoints.values()}
    if len(versions) > 1:
        raise ValueError("Cannot save mixed global checkpoint versions")
    checkpoint_version = next(iter(versions), "")
    payload = {
        "checkpoint_version": checkpoint_version,
        "records": [
            json.loads(checkpoints[sample_id].model_dump_json())
            for sample_id in sorted(checkpoints)
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_path.replace(path)
