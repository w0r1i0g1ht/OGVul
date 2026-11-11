from schemas import BinaryDiagnosis


def recover_historical_binary(raw_text: str) -> BinaryDiagnosis:
    """Reproduce the original KG Step 5A keyword fallback exactly."""
    text_lower = (raw_text or "").lower()
    is_vulnerable = False
    if (
        '"is_vulnerable": true' in text_lower
        or "vulnerable" in text_lower
        or "vulnerability" in text_lower
    ):
        if '"is_vulnerable": false' not in text_lower and "not vulnerable" not in text_lower:
            is_vulnerable = True

    return BinaryDiagnosis(
        graph_warning_critique=(
            "Fallback: Model response was not valid JSON, unable to perform critique."
        ),
        code_logic_analysis=(
            "Fallback: Model response was not valid JSON, unable to perform code logic analysis."
        ),
        is_vulnerable=is_vulnerable,
        confidence=0.5,
    )
