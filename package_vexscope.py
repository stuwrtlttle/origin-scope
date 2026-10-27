#!/usr/bin/env python3
"""Build a portable VEXScope runtime bundle."""

import argparse
import tarfile
from pathlib import Path


RUNTIME_FILES = (
    "vexscope_app.py",
    "cve_report_app.py",
    "cve_report.py",
    "assessment_policy.py",
    "assessment_profiles.json",
    "vex_cache.py",
    "scanner_csv.py",
    "scanner_rationale_rules.json",
)
BUNDLE_DIRECTORY = "vexscope"


def build_archive(destination, source_dir=None):
    """Create a tar.gz containing exactly the VEXScope runtime files."""
    source_dir = Path(source_dir or Path(__file__).resolve().parent)
    destination = Path(destination)
    missing = [name for name in RUNTIME_FILES if not (source_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(f"Cannot package VEXScope; missing: {', '.join(missing)}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        for name in RUNTIME_FILES:
            archive.add(source_dir / name, arcname=f"{BUNDLE_DIRECTORY}/{name}", recursive=False)
    return destination


def main():
    parser = argparse.ArgumentParser(description="Package the VEXScope runtime into a tar.gz archive.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.cwd() / "vexscope-bundle.tar.gz",
        help="Archive path (default: ./vexscope-bundle.tar.gz).",
    )
    args = parser.parse_args()
    archive = build_archive(args.output)
    print(f"Created {archive.resolve()} with {len(RUNTIME_FILES)} VEXScope runtime files.")


if __name__ == "__main__":
    main()
