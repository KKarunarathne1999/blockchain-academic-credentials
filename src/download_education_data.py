"""
Official UK Higher-Education Data Ingestion Pipeline
=====================================================

This module prepares public Office for Students (OfS) data for use
in the blockchain academic credential research project.

The script:

1. Locates a manually downloaded OfS ZIP/CSV dataset.
2. Calculates a SHA-256 checksum of the original source file.
3. Extracts ZIP archives when required.
4. Discovers CSV files.
5. Inspects their structure.
6. Copies usable CSVs into data/raw/.
7. Generates a machine-readable provenance record.

Why manual acquisition initially?
---------------------------------
The Office for Students publishes downloadable CSV packages on its
official website. Download URLs may change as releases are updated.
For reproducible academic research, we record the official source page,
retrieval date, checksum, and local filenames instead of silently
depending on a volatile direct download URL.

Official source:
https://www.officeforstudents.org.uk/data-and-analysis/
size-and-shape-of-provision-data-dashboard/get-the-data/

Important:
The OfS data is public aggregated/statistical information. It does NOT
contain genuine individual academic credentials. Later stages of this
project will use public institutional/course metadata as grounding while
generating synthetic private holder-level credential information.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import zipfile

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
PROVENANCE_DIR = DATA_DIR / "provenance"

DEFAULT_DOWNLOAD_DIR = Path.home() / "Downloads"

SOURCE_NAME = "Office for Students"
DATASET_NAME = "Size and shape of provision data dashboard"

SOURCE_PAGE = (
    "https://www.officeforstudents.org.uk/"
    "data-and-analysis/size-and-shape-of-provision-data-dashboard/"
    "get-the-data/"
)

RESEARCH_PROJECT = (
    "Privacy-Preserving Blockchain Framework for "
    "Decentralized Academic Credential Verification"
)


# ============================================================
# Directory setup
# ============================================================

def create_directories() -> None:
    """Create required project data directories."""

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# SHA-256
# ============================================================

def sha256_file(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Calculate the SHA-256 digest of a file.

    Parameters
    ----------
    file_path:
        Path to the file.
    chunk_size:
        Number of bytes read at once.

    Returns
    -------
    str
        Hexadecimal SHA-256 digest.
    """

    digest = hashlib.sha256()

    with file_path.open("rb") as file_obj:
        while True:
            chunk = file_obj.read(chunk_size)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ============================================================
# File discovery
# ============================================================

def discover_candidate_files(directory: Path) -> list[Path]:
    """
    Discover possible OfS data files.

    Supports ZIP and CSV files.
    """

    if not directory.exists():
        return []

    files: list[Path] = []

    for extension in ("*.zip", "*.csv"):
        files.extend(directory.glob(extension))

    return sorted(
        files,
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def choose_file_interactively(files: list[Path]) -> Path:
    """Allow the user to select a discovered data file."""

    if not files:
        raise FileNotFoundError(
            "No ZIP or CSV files were found in the selected directory."
        )

    print("\nCandidate dataset files:\n")

    for index, path in enumerate(files, start=1):
        size_mb = path.stat().st_size / (1024 * 1024)

        modified = datetime.fromtimestamp(
            path.stat().st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S")

        print(
            f"[{index}] {path.name}\n"
            f"    Size: {size_mb:.2f} MB\n"
            f"    Modified: {modified}"
        )

    print()

    while True:
        choice = input(
            f"Choose dataset file [1-{len(files)}]: "
        ).strip()

        try:
            selected_index = int(choice) - 1

            if 0 <= selected_index < len(files):
                return files[selected_index]

        except ValueError:
            pass

        print("Invalid selection. Please try again.")


# ============================================================
# ZIP extraction
# ============================================================

def extract_zip(zip_path: Path) -> Path:
    """
    Extract a ZIP archive into the project's raw data directory.

    A separate folder is created using the ZIP filename.
    """

    extraction_directory = (
        RAW_DIR / zip_path.stem.replace(" ", "_")
    )

    if extraction_directory.exists():
        shutil.rmtree(extraction_directory)

    extraction_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(f"\nExtracting: {zip_path.name}")
    print(f"Destination: {extraction_directory}")

    with zipfile.ZipFile(zip_path, "r") as archive:

        # Basic path traversal protection
        for member in archive.infolist():
            member_path = (
                extraction_directory / member.filename
            ).resolve()

            if extraction_directory.resolve() not in member_path.parents \
                    and member_path != extraction_directory.resolve():

                raise ValueError(
                    f"Unsafe path detected in ZIP: {member.filename}"
                )

        archive.extractall(extraction_directory)

    return extraction_directory


# ============================================================
# CSV discovery
# ============================================================

def find_csv_files(directory: Path) -> list[Path]:
    """Recursively discover CSV files."""

    return sorted(
        path
        for path in directory.rglob("*.csv")
        if path.is_file()
    )


# ============================================================
# CSV inspection
# ============================================================

def inspect_csv(csv_path: Path) -> dict[str, Any]:
    """
    Inspect a CSV without loading the entire file into memory.

    Only a small sample is loaded for structural inspection.
    """

    result: dict[str, Any] = {
        "file_name": csv_path.name,
        "relative_path": str(csv_path.relative_to(PROJECT_ROOT))
        if PROJECT_ROOT in csv_path.parents
        else str(csv_path),
        "size_bytes": csv_path.stat().st_size,
        "size_mb": round(
            csv_path.stat().st_size / (1024 * 1024),
            4,
        ),
        "sha256": sha256_file(csv_path),
        "readable": False,
        "column_count": None,
        "columns": [],
        "sample_rows": None,
        "encoding": None,
        "error": None,
    }

    encodings_to_try = [
        "utf-8",
        "utf-8-sig",
        "latin-1",
    ]

    for encoding in encodings_to_try:

        try:
            sample = pd.read_csv(
                csv_path,
                nrows=5,
                encoding=encoding,
                low_memory=False,
            )

            result["readable"] = True
            result["column_count"] = len(sample.columns)
            result["columns"] = [
                str(column)
                for column in sample.columns
            ]
            result["sample_rows"] = len(sample)
            result["encoding"] = encoding

            return result

        except Exception as exc:
            result["error"] = str(exc)

    return result


# ============================================================
# Provenance
# ============================================================

def create_provenance_record(
    original_file: Path,
    original_checksum: str,
    csv_inspections: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create a complete dataset provenance object."""

    retrieval_time = datetime.now(
        timezone.utc
    ).isoformat()

    return {
        "research_project": RESEARCH_PROJECT,

        "source": {
            "organisation": SOURCE_NAME,
            "dataset": DATASET_NAME,
            "source_page": SOURCE_PAGE,
            "retrieved_at_utc": retrieval_time,
        },

        "original_download": {
            "file_name": original_file.name,
            "size_bytes": original_file.stat().st_size,
            "size_mb": round(
                original_file.stat().st_size
                / (1024 * 1024),
                4,
            ),
            "sha256": original_checksum,
        },

        "extracted_csv_files": csv_inspections,

        "methodology_note": (
            "The OfS dataset provides public aggregated "
            "higher-education information. Individual student "
            "credential records used later in this research are "
            "generated synthetically and must not be represented "
            "as genuine student records."
        ),
    }


def save_provenance(
    provenance: dict[str, Any]
) -> Path:
    """Save provenance information as JSON."""

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    output_path = (
        PROVENANCE_DIR
        / f"ofs_dataset_provenance_{timestamp}.json"
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file_obj:

        json.dump(
            provenance,
            file_obj,
            indent=2,
            ensure_ascii=False,
        )

    return output_path


# ============================================================
# Copy direct CSV input
# ============================================================

def copy_csv_to_raw(csv_path: Path) -> Path:
    """Copy a directly supplied CSV into data/raw."""

    destination = RAW_DIR / csv_path.name

    if csv_path.resolve() != destination.resolve():
        shutil.copy2(
            csv_path,
            destination,
        )

    return destination


# ============================================================
# Main ingestion pipeline
# ============================================================

def ingest_dataset(input_file: Path) -> None:
    """Run the complete data-ingestion process."""

    create_directories()

    input_file = input_file.expanduser().resolve()

    if not input_file.exists():
        raise FileNotFoundError(
            f"Dataset file does not exist: {input_file}"
        )

    if input_file.suffix.lower() not in {
        ".zip",
        ".csv",
    }:
        raise ValueError(
            "Input must be either a ZIP or CSV file."
        )

    print("=" * 70)
    print("OFFICIAL UK HIGHER-EDUCATION DATA INGESTION")
    print("=" * 70)

    print(f"\nSource organisation: {SOURCE_NAME}")
    print(f"Dataset:             {DATASET_NAME}")
    print(f"Input file:          {input_file}")

    print("\nCalculating original file SHA-256...")

    original_checksum = sha256_file(
        input_file
    )

    print(
        f"SHA-256: {original_checksum}"
    )

    if input_file.suffix.lower() == ".zip":

        extraction_directory = extract_zip(
            input_file
        )

        csv_files = find_csv_files(
            extraction_directory
        )

    else:

        copied_csv = copy_csv_to_raw(
            input_file
        )

        csv_files = [
            copied_csv
        ]

    if not csv_files:
        raise RuntimeError(
            "No CSV files were discovered in the supplied dataset."
        )

    print(
        f"\nCSV files discovered: {len(csv_files)}"
    )

    inspections: list[dict[str, Any]] = []

    for index, csv_path in enumerate(
        csv_files,
        start=1,
    ):

        print(
            f"\n[{index}/{len(csv_files)}] "
            f"Inspecting {csv_path.name}"
        )

        inspection = inspect_csv(
            csv_path
        )

        inspections.append(
            inspection
        )

        print(
            f"    Size:       "
            f"{inspection['size_mb']:.2f} MB"
        )

        print(
            f"    Readable:   "
            f"{inspection['readable']}"
        )

        if inspection["readable"]:

            print(
                f"    Columns:    "
                f"{inspection['column_count']}"
            )

            preview_columns = (
                inspection["columns"][:10]
            )

            print(
                "    First columns: "
                + ", ".join(preview_columns)
            )

    provenance = create_provenance_record(
        original_file=input_file,
        original_checksum=original_checksum,
        csv_inspections=inspections,
    )

    provenance_path = save_provenance(
        provenance
    )

    readable_count = sum(
        1
        for item in inspections
        if item["readable"]
    )

    print("\n" + "=" * 70)
    print("INGESTION SUMMARY")
    print("=" * 70)

    print(
        f"CSV files found:      {len(inspections)}"
    )

    print(
        f"Readable CSV files:   {readable_count}"
    )

    print(
        f"Original SHA-256:     {original_checksum}"
    )

    print(
        f"Provenance metadata:  {provenance_path}"
    )

    print("\nData ingestion completed successfully.")


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Ingest official Office for Students "
            "higher-education data."
        )
    )

    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help=(
            "Path to an OfS ZIP or CSV file. "
            "If omitted, the script searches ~/Downloads."
        ),
    )

    parser.add_argument(
        "--directory",
        type=Path,
        default=DEFAULT_DOWNLOAD_DIR,
        help=(
            "Directory searched interactively when "
            "--file is not supplied."
        ),
    )

    return parser.parse_args()


def main() -> None:
    """Application entry point."""

    args = parse_arguments()

    try:

        if args.file is not None:

            selected_file = args.file

        else:

            candidate_files = discover_candidate_files(
                args.directory.expanduser()
            )

            if not candidate_files:

                print(
                    "\nNo ZIP or CSV files were found in:"
                )

                print(
                    args.directory.expanduser()
                )

                print(
                    "\nDownload the official OfS "
                    "'Size and shape of provision' "
                    "CSV package first:"
                )

                print(
                    SOURCE_PAGE
                )

                sys.exit(1)

            selected_file = (
                choose_file_interactively(
                    candidate_files
                )
            )

        ingest_dataset(
            selected_file
        )

    except KeyboardInterrupt:

        print("\nOperation cancelled.")

        sys.exit(130)

    except Exception as exc:

        print(
            f"\nERROR: {exc}"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()