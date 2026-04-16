#!/usr/bin/env python3
"""
Dataset: kanakbaghel/hospital-management-dataset
File: appointments.csv

"""

from __future__ import annotations

import shutil
from pathlib import Path

import kagglehub


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = repo_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    src_root = Path(kagglehub.dataset_download("kanakbaghel/hospital-management-dataset"))
    src = src_root / "appointments.csv"
    dst = data_dir / "appointments.csv"

    if not src.exists():
        raise SystemExit(f"appointments.csv not found at {src}")

    shutil.copyfile(src, dst)
    print(f"Copied {src} -> {dst}")


if __name__ == "__main__":
    main()

