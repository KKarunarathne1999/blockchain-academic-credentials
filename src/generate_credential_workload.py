"""
Scalable Academic Credential Workload Generator
================================================

Generates reproducible synthetic academic credential workloads grounded
in official Office for Students (OfS) provider-level statistics.

REAL PUBLIC INFORMATION
-----------------------
- UK provider identifiers (UKPRNs)
- Relative provider-size information derived from OfS student counts

SYNTHETIC INFORMATION
---------------------
- Holder identifiers
- Credential identifiers
- Degree programmes
- Award classifications
- Graduation years
- DID identifiers
- Credential status

The generated records MUST NOT be interpreted as genuine student
records or genuine credentials issued by the corresponding providers.

Purpose
-------
The datasets are experimental workloads for evaluating blockchain-based
academic credential issuance, verification, revocation, privacy and
scalability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
GENERATED_DIR = PROJECT_ROOT / "data" / "generated"
PROVENANCE_DIR = PROJECT_ROOT / "data" / "provenance"

PROVIDER_FILE = (
    PROCESSED_DIR / "ofs_provider_workload.csv"
)

DEFAULT_SIZE = 10_000
DEFAULT_SEED = 42

SUPPORTED_SIZES = {
    1_000,
    10_000,
    50_000,
    100_000,
    500_000,
}


# ============================================================
# Synthetic academic configuration
# ============================================================

UNDERGRADUATE_PROGRAMMES = [
    "BSc Computer Science",
    "BSc Data Science",
    "BSc Artificial Intelligence",
    "BSc Cyber Security",
    "BSc Software Engineering",
    "BSc Information Technology",
    "BSc Business Information Systems",
    "BSc Mathematics",
]

POSTGRADUATE_PROGRAMMES = [
    "MSc Computer Science",
    "MSc Data Science",
    "MSc Artificial Intelligence",
    "MSc Cyber Security",
    "MSc Software Engineering",
    "MSc Business Analytics",
    "MSc Information Technology",
]

UNDERGRADUATE_CLASSIFICATIONS = [
    "First Class",
    "Upper Second Class",
    "Lower Second Class",
    "Third Class",
]

UNDERGRADUATE_CLASSIFICATION_PROBABILITIES = [
    0.30,
    0.45,
    0.20,
    0.05,
]

POSTGRADUATE_CLASSIFICATIONS = [
    "Distinction",
    "Merit",
    "Pass",
]

POSTGRADUATE_CLASSIFICATION_PROBABILITIES = [
    0.25,
    0.45,
    0.30,
]

GRADUATION_YEARS = np.array(
    [2021, 2022, 2023, 2024, 2025, 2026]
)

GRADUATION_YEAR_PROBABILITIES = np.array(
    [0.10, 0.13, 0.16, 0.19, 0.21, 0.21]
)


# ============================================================
# Utility
# ============================================================

def sha256_file(
    file_path: Path,
    chunk_size: int = 1024 * 1024,
) -> str:
    """Calculate SHA-256 checksum."""

    digest = hashlib.sha256()

    with file_path.open("rb") as file_obj:

        while True:

            chunk = file_obj.read(chunk_size)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ============================================================
# Provider data
# ============================================================

def load_provider_distribution() -> pd.DataFrame:
    """
    Load and validate the processed OfS provider workload.

    Providers without positive latest-year counts are excluded because
    the public student count is used only as a relative sampling weight.
    """

    if not PROVIDER_FILE.exists():

        raise FileNotFoundError(
            "Processed provider workload does not exist.\n"
            "Run first:\n"
            "python src/preprocess_education_data.py"
        )

    df = pd.read_csv(
        PROVIDER_FILE
    )

    required = {
        "UKPRN",
        "STUDENT_COUNT_2024_25",
    }

    missing = required - set(df.columns)

    if missing:

        raise ValueError(
            "Provider workload is missing columns: "
            + ", ".join(sorted(missing))
        )

    df["UKPRN"] = pd.to_numeric(
        df["UKPRN"],
        errors="coerce",
    )

    df["STUDENT_COUNT_2024_25"] = pd.to_numeric(
        df["STUDENT_COUNT_2024_25"],
        errors="coerce",
    )

    df = df.dropna(
        subset=[
            "UKPRN",
            "STUDENT_COUNT_2024_25",
        ]
    )

    df = df[
        df["STUDENT_COUNT_2024_25"] > 0
    ].copy()

    df["UKPRN"] = df["UKPRN"].astype(
        "int64"
    )

    total_students = (
        df["STUDENT_COUNT_2024_25"].sum()
    )

    if total_students <= 0:

        raise ValueError(
            "Provider student counts do not produce "
            "a valid sampling distribution."
        )

    df["SAMPLING_WEIGHT"] = (
        df["STUDENT_COUNT_2024_25"]
        / total_students
    )

    return df.reset_index(
        drop=True
    )


# ============================================================
# DID generation
# ============================================================

def create_holder_did(
    holder_number: int,
) -> str:
    """
    Create a deterministic research-only holder DID.

    did:example is intentionally used because these are synthetic
    identities and are not intended for production DID resolution.
    """

    return (
        f"did:example:holder:"
        f"{holder_number:012d}"
    )


def create_issuer_did(
    ukprn: int,
) -> str:
    """
    Create a deterministic research issuer identifier.

    This links the experimental issuer identity to a genuine public
    UKPRN without claiming that the real provider controls this DID.
    """

    return (
        f"did:example:issuer:"
        f"ukprn-{ukprn}"
    )


# ============================================================
# Credential generation
# ============================================================

def generate_credentials(
    size: int,
    seed: int,
    providers: pd.DataFrame,
) -> pd.DataFrame:
    """Generate a reproducible credential workload."""

    rng = np.random.default_rng(
        seed
    )

    random.seed(seed)

    ukprns = providers[
        "UKPRN"
    ].to_numpy()

    weights = providers[
        "SAMPLING_WEIGHT"
    ].to_numpy()

    selected_providers = rng.choice(
        ukprns,
        size=size,
        replace=True,
        p=weights,
    )

    # Approximately 75% UG / 25% PG.
    levels = rng.choice(
        np.array(
            ["Undergraduate", "Postgraduate"]
        ),
        size=size,
        p=[0.75, 0.25],
    )

    graduation_years = rng.choice(
        GRADUATION_YEARS,
        size=size,
        p=GRADUATION_YEAR_PROBABILITIES,
    )

    records: list[dict[str, Any]] = []

    for index in range(size):

        credential_number = index + 1

        level = str(
            levels[index]
        )

        ukprn = int(
            selected_providers[index]
        )

        if level == "Undergraduate":

            programme = str(
                rng.choice(
                    UNDERGRADUATE_PROGRAMMES
                )
            )

            classification = str(
                rng.choice(
                    UNDERGRADUATE_CLASSIFICATIONS,
                    p=(
                        UNDERGRADUATE_CLASSIFICATION_PROBABILITIES
                    ),
                )
            )

        else:

            programme = str(
                rng.choice(
                    POSTGRADUATE_PROGRAMMES
                )
            )

            classification = str(
                rng.choice(
                    POSTGRADUATE_CLASSIFICATIONS,
                    p=(
                        POSTGRADUATE_CLASSIFICATION_PROBABILITIES
                    ),
                )
            )

        records.append(
            {
                "credential_id": (
                    f"CRED-{credential_number:012d}"
                ),

                "holder_id": (
                    f"HOLDER-{credential_number:012d}"
                ),

                "holder_did": create_holder_did(
                    credential_number
                ),

                "issuer_ukprn": ukprn,

                "issuer_did": create_issuer_did(
                    ukprn
                ),

                "qualification_level": level,

                "programme": programme,

                "classification": classification,

                "graduation_year": int(
                    graduation_years[index]
                ),

                "credential_status": "active",
            }
        )

    return pd.DataFrame(
        records
    )


# ============================================================
# Validation
# ============================================================

def validate_workload(
    df: pd.DataFrame,
    expected_size: int,
) -> dict[str, Any]:
    """Validate generated credential workload."""

    duplicate_credentials = int(
        df["credential_id"].duplicated().sum()
    )

    duplicate_holders = int(
        df["holder_id"].duplicated().sum()
    )

    missing_values = int(
        df.isna().sum().sum()
    )

    unknown_status = int(
        (~df["credential_status"].isin(["active"])).sum()
    )

    if len(df) != expected_size:

        raise ValueError(
            "Generated row count does not match "
            "requested workload size."
        )

    if duplicate_credentials != 0:

        raise ValueError(
            "Duplicate credential IDs detected."
        )

    if duplicate_holders != 0:

        raise ValueError(
            "Duplicate holder IDs detected."
        )

    if missing_values != 0:

        raise ValueError(
            "Generated workload contains missing values."
        )

    if unknown_status != 0:

        raise ValueError(
            "Unexpected credential status detected."
        )

    return {
        "records": int(len(df)),

        "unique_credentials": int(
            df["credential_id"].nunique()
        ),

        "unique_holders": int(
            df["holder_id"].nunique()
        ),

        "unique_issuers": int(
            df["issuer_ukprn"].nunique()
        ),

        "undergraduate_credentials": int(
            (
                df["qualification_level"]
                == "Undergraduate"
            ).sum()
        ),

        "postgraduate_credentials": int(
            (
                df["qualification_level"]
                == "Postgraduate"
            ).sum()
        ),

        "duplicate_credentials": (
            duplicate_credentials
        ),

        "duplicate_holders": (
            duplicate_holders
        ),

        "missing_values": missing_values,
    }


# ============================================================
# Save workload
# ============================================================

def save_workload(
    df: pd.DataFrame,
    size: int,
    seed: int,
) -> Path:
    """Save generated credential workload."""

    GENERATED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        GENERATED_DIR
        / (
            f"academic_credentials_"
            f"n{size}_seed{seed}.csv"
        )
    )

    df.to_csv(
        output_path,
        index=False,
    )

    return output_path


# ============================================================
# Manifest
# ============================================================

def save_manifest(
    output_path: Path,
    size: int,
    seed: int,
    providers: pd.DataFrame,
    validation: dict[str, Any],
) -> Path:
    """Save reproducibility manifest."""

    PROVENANCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    manifest_path = (
        PROVENANCE_DIR
        / (
            f"credential_workload_"
            f"n{size}_seed{seed}_"
            f"{timestamp}.json"
        )
    )

    manifest = {
        "created_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "generator": (
            "src/generate_credential_workload.py"
        ),

        "random_seed": seed,

        "requested_credentials": size,

        "data_grounding": {
            "source": (
                "Office for Students "
                "provider-level public statistics"
            ),

            "provider_file": str(
                PROVIDER_FILE.relative_to(
                    PROJECT_ROOT
                )
            ),

            "provider_file_sha256": sha256_file(
                PROVIDER_FILE
            ),

            "eligible_providers": int(
                len(providers)
            ),

            "weighting_variable": (
                "STUDENT_COUNT_2024_25"
            ),
        },

        "synthetic_fields": [
            "credential_id",
            "holder_id",
            "holder_did",
            "issuer_did",
            "qualification_level",
            "programme",
            "classification",
            "graduation_year",
            "credential_status",
        ],

        "public_grounding_fields": [
            "issuer_ukprn",
            "relative provider sampling weight",
        ],

        "validation": validation,

        "output": {
            "path": str(
                output_path.relative_to(
                    PROJECT_ROOT
                )
            ),

            "sha256": sha256_file(
                output_path
            ),

            "size_bytes": (
                output_path.stat().st_size
            ),
        },

        "methodology_note": (
            "The generated dataset is a synthetic research "
            "workload. Genuine OfS UKPRNs and aggregated "
            "provider-size statistics are used solely to "
            "ground the issuer distribution. The generated "
            "records do not represent real students, real "
            "degrees, or credentials issued by those providers."
        ),
    }

    with manifest_path.open(
        "w",
        encoding="utf-8",
    ) as file_obj:

        json.dump(
            manifest,
            file_obj,
            indent=2,
            ensure_ascii=False,
        )

    return manifest_path


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Generate reproducible academic "
            "credential research workloads."
        )
    )

    parser.add_argument(
        "--size",
        type=int,
        default=DEFAULT_SIZE,
        help=(
            "Number of credentials to generate. "
            "Recommended experiment sizes: "
            "1000, 10000, 50000, 100000, 500000."
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed.",
    )

    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main() -> None:
    """Run credential workload generation."""

    args = parse_arguments()

    if args.size <= 0:

        raise ValueError(
            "--size must be greater than zero."
        )

    print("=" * 72)
    print("ACADEMIC CREDENTIAL RESEARCH WORKLOAD GENERATOR")
    print("=" * 72)

    print(
        f"\nRequested credentials: {args.size:,}"
    )

    print(
        f"Random seed:          {args.seed}"
    )

    if args.size not in SUPPORTED_SIZES:

        print(
            "\nNOTE: This is a custom workload size. "
            "Recommended experimental sizes are "
            "1K, 10K, 50K, 100K and 500K."
        )

    print(
        "\nLoading real OfS provider distribution..."
    )

    providers = load_provider_distribution()

    print(
        f"Eligible providers:   {len(providers):,}"
    )

    print(
        "\nGenerating synthetic credentials..."
    )

    credentials = generate_credentials(
        size=args.size,
        seed=args.seed,
        providers=providers,
    )

    print(
        "Validating generated workload..."
    )

    validation = validate_workload(
        credentials,
        args.size,
    )

    print(
        "Saving credential workload..."
    )

    output_path = save_workload(
        credentials,
        args.size,
        args.seed,
    )

    manifest_path = save_manifest(
        output_path,
        args.size,
        args.seed,
        providers,
        validation,
    )

    print("\n" + "=" * 72)
    print("WORKLOAD SUMMARY")
    print("=" * 72)

    print(
        f"Credentials:        "
        f"{validation['records']:,}"
    )

    print(
        f"Unique holders:     "
        f"{validation['unique_holders']:,}"
    )

    print(
        f"Unique issuers:     "
        f"{validation['unique_issuers']:,}"
    )

    print(
        f"Undergraduate:      "
        f"{validation['undergraduate_credentials']:,}"
    )

    print(
        f"Postgraduate:       "
        f"{validation['postgraduate_credentials']:,}"
    )

    print(
        f"Missing values:     "
        f"{validation['missing_values']:,}"
    )

    print(
        f"Duplicate IDs:      "
        f"{validation['duplicate_credentials']:,}"
    )

    print(
        f"\nDataset:\n  {output_path}"
    )

    print(
        f"\nManifest:\n  {manifest_path}"
    )

    print(
        f"\nDataset SHA-256:\n  "
        f"{sha256_file(output_path)}"
    )

    print(
        "\nCredential workload generation "
        "completed successfully."
    )


if __name__ == "__main__":
    main()