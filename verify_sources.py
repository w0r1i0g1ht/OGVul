"""Verify that historical source files still match their recovered snapshots."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    manifest = json.loads((ROOT / "source_manifest.json").read_text(encoding="utf-8"))
    failed = []
    for relative_path, expected in manifest.items():
        path = ROOT / relative_path
        actual = sha256(path) if path.exists() else "missing"
        status = "OK" if actual == expected else "MISMATCH"
        print(f"{status:8} {relative_path}")
        if status != "OK":
            failed.append((relative_path, expected, actual))
    if failed:
        details = "\n".join(
            f"{path}: expected={expected}, actual={actual}"
            for path, expected, actual in failed
        )
        raise SystemExit(f"Historical source verification failed:\n{details}")


if __name__ == "__main__":
    main()
