import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

from .build import build
from .ingest import ingest, verify
from .skew import skew


def _handle_remove_readonly(func, path, exc_info):
    """Clear the readonly bit and reattempt removing the file (Windows support)."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def run_case(
    sources_json: Path,
    case_dir: Path,
    collector: str = "pipeline",
    reference_host: str | None = None,
) -> dict[str, Any]:
    # 1. if case_dir exists, delete it with shutil.rmtree using an onerror handler that does os.chmod(path, stat.S_IWRITE) and retries
    if case_dir.exists():
        try:
            shutil.rmtree(case_dir, onexc=_handle_remove_readonly)
        except TypeError:
            shutil.rmtree(case_dir, onerror=_handle_remove_readonly)

    # Read case_id from sources.json
    with open(sources_json, "r", encoding="utf-8") as f:
        spec = json.load(f)
    case_id = spec["case_id"]

    # 2. ingest(case_dir, sources_json, collector)
    ingest(case_dir, sources_json, collector)

    # 3. assert verify(case_dir) is True, else raise RuntimeError("evidence verification failed")
    if not verify(case_dir):
        raise RuntimeError("evidence verification failed")

    # 4. stats = build(case_dir)
    stats = build(case_dir)

    # 5. rows = skew(case_dir, reference_host=reference_host)
    rows = skew(case_dir, reference_host=reference_host)

    # return {"case_id": <from sources.json>, "verified": True, "build": stats, "skew": rows}
    return {
        "case_id": case_id,
        "verified": True,
        "build": stats,
        "skew": rows,
    }
