"""
Preprocess Official UK Higher-Education Data
=============================================

This module prepares Office for Students (OfS) public datasets for use
in the academic credential blockchain research project.

The script:

1. Discovers the official OfS CSV files inside data/raw/.
2. Ignores macOS metadata files and __MACOSX directories.
3. Loads student-number and size-and-shape datasets.
4. Normalises missing/suppressed OfS values.
5. Converts count and percentage fields to numeric values.
6. Extracts institution-level workload information.
7. Produces compact processed datasets suitable for later credential
   workload generation.
8. Writes preprocessing metadata for reproducibility.

Important
---------
These OfS datasets contain public aggregated higher-education statistics.
They do not represent individual students or actual academic credentials.
Private holder-level credential records will be generated synthetically
in a later stage.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
PROVENANCE_DIR = PROJECT_ROOT / "data" / "provenance"


# ============================================================
# Expected source filenames
# ============================================================

STUDENT_NUMBERS_PATTERN = "Student_numbers_all_providers_*.csv"
SIZE_SHAPE_PATTERN = "Size_and_shape_all_providers_*.csv"


# ============================================================
# OfS suppressed / unavailable values
# ============================================================

SPECIAL_VALUES = {
    "[DPL]": pd.NA,
    "[N/A]": pd.NA,
    "[none]": pd.NA,
    "[NONE]": pd.NA,
    "": pd.NA,
}


# ============================================================
# Utility functions
# ============================================================

def sha256_file(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Return the SHA-256 checksum of a file."""

    digest = hashlib.sha256()

    with file_path.open("rb") as file_obj:
        while True:
            chunk = file_obj.read(chunk_size)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def discover_source_file(pattern: str) -> Path:
    """
    Locate exactly one matching OfS CSV.

    Files inside __MACOSX directories and files beginning with '._'
    are ignored.
    """

    matches = []

    for path in RAW_DIR.rglob(pattern):

        if "__MACOSX" in path.parts:
            continue

        if path.name.startswith("._"):
            continue

        if path.is_file():
            matches.append(path)

    if not matches:
        raise FileNotFoundError(
            f"No file matching '{pattern}' was found under {RAW_DIR}"
        )

    if len(matches) > 1:
        print(
            f"WARNING: {len(matches)} files matched '{pattern}'. "
            "Using the newest file."
        )

        matches.sort(
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

    return matches[0]


def load_csv(file_path: Path) -> pd.DataFrame:
    """Load an OfS CSV with appropriate missing-value handling."""

    print(f"Loading: {file_path.name}")

    df = pd.read_csv(
        file_path,
        dtype=str,
        low_memory=False,
        na_values=list(SPECIAL_VALUES.keys()),
        keep_default_na=True,
    )

    df.columns = [
        column.strip()
        for column in df.columns
    ]

    return df


def convert_numeric_columns(
    df: pd.DataFrame,
    prefixes: tuple[str, ...],
) -> pd.DataFrame:
    """
    Convert columns beginning with specified prefixes to numeric.

    Invalid or suppressed values become NaN.
    """

    result = df.copy()

    for column in result.columns:

        if column.startswith(prefixes):

            result[column] = pd.to_numeric(
                result[column],
                errors="coerce",
            )

    return result


# ============================================================
# Student-number preprocessing
# ============================================================

def preprocess_student_numbers(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Prepare the OfS student-number dataset.

    We retain the public provider identifier and the latest available
    2024-25 counts needed to derive realistic credential workload sizes.
    """

    required_columns = [
        "UKPRN",
        "COHORT",
        "TYPE_OF_PROVISION",
        "LEVEL_OF_STUDY",
        "COUNT_2024_25",
        "PERCENT_2024_25",
        "COUNT_ALL_YEARS",
        "PERCENT_ALL_YEARS",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            "Student-number dataset is missing required columns: "
            + ", ".join(missing_columns)
        )

    result = df[
        required_columns
    ].copy()

    result = convert_numeric_columns(
        result,
        prefixes=("COUNT_", "PERCENT_"),
    )

    result["UKPRN"] = pd.to_numeric(
        result["UKPRN"],
        errors="coerce",
    ).astype("Int64")

    result = result.dropna(
        subset=["UKPRN"]
    )

    result = result.drop_duplicates()

    return result


# ============================================================
# Provider workload extraction
# ============================================================

def create_provider_workload_table(
    student_numbers: pd.DataFrame,
) -> pd.DataFrame:
    """
    Create one row per provider using the latest available student count.

    The preferred source row is:

        COHORT = All students
        TYPE_OF_PROVISION = Full-time
        LEVEL_OF_STUDY = Full-time (total)

    This is not interpreted as the number of credentials issued.
    It is used later only as a realistic weighting signal when
    generating research credential workloads.
    """

    mask = (
        student_numbers["COHORT"]
        .fillna("")
        .str.strip()
        .eq("All students")
        &
        student_numbers["TYPE_OF_PROVISION"]
        .fillna("")
        .str.strip()
        .eq("Full-time")
        &
        student_numbers["LEVEL_OF_STUDY"]
        .fillna("")
        .str.strip()
        .eq("Full-time (total)")
    )

    workload = student_numbers.loc[
        mask,
        [
            "UKPRN",
            "COUNT_2024_25",
            "COUNT_ALL_YEARS",
        ],
    ].copy()

    workload = workload.rename(
        columns={
            "COUNT_2024_25": "STUDENT_COUNT_2024_25",
            "COUNT_ALL_YEARS": "STUDENT_COUNT_ALL_YEARS",
        }
    )

    workload = workload.drop_duplicates(
        subset=["UKPRN"]
    )

    workload = workload.sort_values(
        by="STUDENT_COUNT_2024_25",
        ascending=False,
        na_position="last",
    )

    workload = workload.reset_index(
        drop=True
    )

    return workload


# ============================================================
# Size-and-shape preprocessing
# ============================================================

def preprocess_size_shape(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Prepare demographic and provider-level public OfS characteristics.

    Only fields potentially useful for later workload realism are kept.
    """

    required_columns = [
        "UKPRN",
        "BASE_YEAR",
        "COHORT",
        "CHARACTERISTIC",
        "ATTRIBUTE",
        "FT_UG_COUNT",
        "PT_UG_COUNT",
        "APPR_UG_COUNT",
        "FT_PG_COUNT",
        "PT_PG_COUNT",
        "APPR_PG_COUNT",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            "Size-and-shape dataset is missing required columns: "
            + ", ".join(missing_columns)
        )

    result = df[
        required_columns
    ].copy()

    result = convert_numeric_columns(
        result,
        prefixes=(
            "FT_",
            "PT_",
            "APPR_",
        ),
    )

    result["UKPRN"] = pd.to_numeric(
        result["UKPRN"],
        errors="coerce",
    ).astype("Int64")

    result["BASE_YEAR"] = pd.to_numeric(
        result["BASE_YEAR"],
        errors="coerce",
    ).astype("Int64")

    result = result.dropna(
        subset=["UKPRN"]
    )

    result = result.drop_duplicates()

    return result


# ============================================================
# Dataset summary
# ============================================================

def dataset_summary(
    student_numbers: pd.DataFrame,
    workload: pd.DataFrame,
    size_shape: pd.DataFrame,
) -> dict[str, Any]:
    """Create summary statistics for reproducibility."""

    return {
        "student_numbers_rows": int(
            len(student_numbers)
        ),
        "student_numbers_providers": int(
            student_numbers["UKPRN"].nunique()
        ),
        "provider_workload_rows": int(
            len(workload)
        ),
        "size_shape_rows": int(
            len(size_shape)
        ),
        "size_shape_providers": int(
            size_shape["UKPRN"].nunique()
        ),
        "base_years": sorted(
            [
                int(value)
                for value
                in size_shape["BASE_YEAR"]
                .dropna()
                .unique()
            ]
        ),
        "characteristics": sorted(
            [
                str(value)
                for value
                in size_shape["CHARACTERISTIC"]
                .dropna()
                .unique()
            ]
        ),
    }


# ============================================================
# Save data
# ============================================================

def save_processed_data(
    student_numbers: pd.DataFrame,
    workload: pd.DataFrame,
    size_shape: pd.DataFrame,
) -> dict[str, Path]:
    """Save processed datasets."""

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    student_numbers_path = (
        PROCESSED_DIR
        / "ofs_student_numbers_clean.csv"
    )

    provider_workload_path = (
        PROCESSED_DIR
        / "ofs_provider_workload.csv"
    )

    size_shape_path = (
        PROCESSED_DIR
        / "ofs_size_shape_clean.csv"
    )

    student_numbers.to_csv(
        student_numbers_path,
        index=False,
    )

    workload.to_csv(
        provider_workload_path,
        index=False,
    )

    size_shape.to_csv(
        size_shape_path,
        index=False,
    )

    return {
        "student_numbers": student_numbers_path,
        "provider_workload": provider_workload_path,
        "size_shape": size_shape_path,
    }


# ============================================================
# Preprocessing provenance
# ============================================================

def save_preprocessing_metadata(
    student_numbers_source: Path,
    size_shape_source: Path,
    summary: dict[str, Any],
    output_paths: dict[str, Path],
) -> Path:
    """Write machine-readable preprocessing metadata."""

    PROVENANCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    metadata_path = (
        PROVENANCE_DIR
        / f"ofs_preprocessing_{timestamp}.json"
    )

    metadata = {
        "created_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "sources": {
            "student_numbers": {
                "filename": student_numbers_source.name,
                "sha256": sha256_file(
                    student_numbers_source
                ),
            },
            "size_and_shape": {
                "filename": size_shape_source.name,
                "sha256": sha256_file(
                    size_shape_source
                ),
            },
        },

        "transformations": [
            "Ignored __MACOSX metadata files.",
            "Converted OfS suppression markers to missing values.",
            "Converted count and percentage columns to numeric types.",
            "Removed rows without valid UKPRNs.",
            "Removed duplicate rows.",
            (
                "Derived provider workload weighting from "
                "All students / Full-time / Full-time (total)."
            ),
        ],

        "summary": summary,

        "outputs": {
            name: str(
                path.relative_to(PROJECT_ROOT)
            )
            for name, path
            in output_paths.items()
        },

        "research_note": (
            "Provider workload counts are public aggregated statistics "
            "used only as weighting information for synthetic credential "
            "generation. They must not be interpreted as actual numbers "
            "of credentials issued."
        ),
    }

    with metadata_path.open(
        "w",
        encoding="utf-8",
    ) as file_obj:

        json.dump(
            metadata,
            file_obj,
            indent=2,
            ensure_ascii=False,
        )

    return metadata_path


# ============================================================
# Main pipeline
# ============================================================

def main() -> None:
    """Run the complete preprocessing pipeline."""

    print("=" * 70)
    print("OFS HIGHER-EDUCATION DATA PREPROCESSING")
    print("=" * 70)

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    PROVENANCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("\nDiscovering source datasets...")

    student_numbers_source = discover_source_file(
        STUDENT_NUMBERS_PATTERN
    )

    size_shape_source = discover_source_file(
        SIZE_SHAPE_PATTERN
    )

    print(
        f"Student numbers: {student_numbers_source.name}"
    )

    print(
        f"Size and shape:  {size_shape_source.name}"
    )

    print("\nLoading datasets...")

    raw_student_numbers = load_csv(
        student_numbers_source
    )

    raw_size_shape = load_csv(
        size_shape_source
    )

    print(
        f"\nRaw student-number rows: "
        f"{len(raw_student_numbers):,}"
    )

    print(
        f"Raw size-and-shape rows: "
        f"{len(raw_size_shape):,}"
    )

    print("\nPreprocessing student-number data...")

    student_numbers = preprocess_student_numbers(
        raw_student_numbers
    )

    print(
        f"Clean student-number rows: "
        f"{len(student_numbers):,}"
    )

    print("\nCreating provider workload table...")

    provider_workload = create_provider_workload_table(
        student_numbers
    )

    print(
        f"Providers with workload information: "
        f"{len(provider_workload):,}"
    )

    print("\nPreprocessing size-and-shape data...")

    size_shape = preprocess_size_shape(
        raw_size_shape
    )

    print(
        f"Clean size-and-shape rows: "
        f"{len(size_shape):,}"
    )

    summary = dataset_summary(
        student_numbers,
        provider_workload,
        size_shape,
    )

    print("\nSaving processed datasets...")

    output_paths = save_processed_data(
        student_numbers,
        provider_workload,
        size_shape,
    )

    metadata_path = save_preprocessing_metadata(
        student_numbers_source,
        size_shape_source,
        summary,
        output_paths,
    )

    print("\n" + "=" * 70)
    print("PREPROCESSING SUMMARY")
    print("=" * 70)

    print(
        f"Student-number providers: "
        f"{summary['student_numbers_providers']:,}"
    )

    print(
        f"Provider workload records: "
        f"{summary['provider_workload_rows']:,}"
    )

    print(
        f"Size/shape providers: "
        f"{summary['size_shape_providers']:,}"
    )

    print(
        "Base years: "
        + ", ".join(
            str(year)
            for year
            in summary["base_years"]
        )
    )

    print(
        f"\nStudent numbers output:\n"
        f"  {output_paths['student_numbers']}"
    )

    print(
        f"\nProvider workload output:\n"
        f"  {output_paths['provider_workload']}"
    )

    print(
        f"\nSize/shape output:\n"
        f"  {output_paths['size_shape']}"
    )

    print(
        f"\nPreprocessing metadata:\n"
        f"  {metadata_path}"
    )

    print(
        "\nPreprocessing completed successfully."
    )


if __name__ == "__main__":
    main()