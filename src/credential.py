"""
Academic Verifiable Credential Builder
=======================================

Constructs W3C Verifiable Credentials Data Model v2.0 credential
documents from the synthetic academic credential research workload.

This module creates UNSIGNED credential documents.

Cryptographic proofs are intentionally handled separately so that the
research implementation clearly distinguishes:

    credential data model
        ↓
    cryptographic proof
        ↓
    blockchain commitment/status

The generated credentials are research artefacts and do not represent
real credentials issued by the UK providers referenced by UKPRN.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd


# ============================================================
# Project configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

GENERATED_DATA_DIR = PROJECT_ROOT / "data" / "generated"

CREDENTIAL_OUTPUT_DIR = (
    PROJECT_ROOT / "credentials" / "unsigned"
)

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"


# ============================================================
# Research academic vocabulary
# ============================================================

ACADEMIC_CONTEXT = {
    "@vocab": "https://example.org/research/academic-credentials#",

    "AcademicCredential": (
        "https://example.org/research/"
        "academic-credentials#AcademicCredential"
    ),

    "issuerUkprn": (
        "https://example.org/research/"
        "academic-credentials#issuerUkprn"
    ),

    "qualificationLevel": (
        "https://example.org/research/"
        "academic-credentials#qualificationLevel"
    ),

    "programme": (
        "https://example.org/research/"
        "academic-credentials#programme"
    ),

    "classification": (
        "https://example.org/research/"
        "academic-credentials#classification"
    ),

    "graduationYear": (
        "https://example.org/research/"
        "academic-credentials#graduationYear"
    ),
}


# ============================================================
# Validation
# ============================================================

REQUIRED_WORKLOAD_FIELDS = {
    "credential_id",
    "holder_id",
    "holder_did",
    "issuer_ukprn",
    "issuer_did",
    "qualification_level",
    "programme",
    "classification",
    "graduation_year",
    "credential_status",
}


def validate_workload_record(
    record: dict[str, Any],
) -> None:
    """Validate a source workload record."""

    missing = REQUIRED_WORKLOAD_FIELDS - set(record)

    if missing:
        raise ValueError(
            "Credential workload record is missing fields: "
            + ", ".join(sorted(missing))
        )

    for field in REQUIRED_WORKLOAD_FIELDS:
        value = record[field]

        if value is None:
            raise ValueError(
                f"Required field '{field}' is None."
            )

        if isinstance(value, float) and pd.isna(value):
            raise ValueError(
                f"Required field '{field}' is NaN."
            )

    if not str(record["holder_did"]).startswith("did:"):
        raise ValueError(
            "holder_did must be a DID identifier."
        )

    if not str(record["issuer_did"]).startswith("did:"):
        raise ValueError(
            "issuer_did must be a DID identifier."
        )

    if record["credential_status"] != "active":
        raise ValueError(
            "Only active credentials can currently be constructed."
        )


# ============================================================
# VC construction
# ============================================================

def build_academic_credential(
    record: dict[str, Any],
    valid_from: str,
) -> dict[str, Any]:
    """
    Convert one workload record into an unsigned VC 2.0 document.

    The credential contains:

    - W3C VC 2.0 base context
    - project research vocabulary
    - credential identifier
    - credential type
    - issuer DID
    - validity timestamp
    - credential subject claims

    No cryptographic proof is added by this function.
    """

    validate_workload_record(record)

    credential_id = str(
        record["credential_id"]
    )

    holder_did = str(
        record["holder_did"]
    )

    issuer_did = str(
        record["issuer_did"]
    )

    ukprn = int(
        record["issuer_ukprn"]
    )

    graduation_year = int(
        record["graduation_year"]
    )

    credential = {
        "@context": [
            VC_CONTEXT,
            ACADEMIC_CONTEXT,
        ],

        "id": (
            "urn:academic-credential:"
            + credential_id.lower()
        ),

        "type": [
            "VerifiableCredential",
            "AcademicCredential",
        ],

        "issuer": issuer_did,

        "validFrom": valid_from,

        "credentialSubject": {
            "id": holder_did,

            "issuerUkprn": str(
                ukprn
            ),

            "qualificationLevel": str(
                record["qualification_level"]
            ),

            "programme": str(
                record["programme"]
            ),

            "classification": str(
                record["classification"]
            ),

            "graduationYear": graduation_year,
        },
    }

    return credential


# ============================================================
# VC structural validation
# ============================================================

def validate_credential_structure(
    credential: dict[str, Any],
) -> None:
    """
    Perform local structural checks.

    This is NOT cryptographic verification and is NOT a complete
    W3C conformance test.
    """

    required_properties = {
        "@context",
        "id",
        "type",
        "issuer",
        "validFrom",
        "credentialSubject",
    }

    missing = (
        required_properties
        - set(credential)
    )

    if missing:
        raise ValueError(
            "Credential is missing properties: "
            + ", ".join(sorted(missing))
        )

    context = credential["@context"]

    if not isinstance(context, list):
        raise ValueError(
            "@context must be an ordered list."
        )

    if not context:
        raise ValueError(
            "@context cannot be empty."
        )

    if context[0] != VC_CONTEXT:
        raise ValueError(
            "W3C VC v2 context must be the first context."
        )

    credential_types = credential["type"]

    if not isinstance(
        credential_types,
        list,
    ):
        raise ValueError(
            "type must be a list."
        )

    if "VerifiableCredential" not in credential_types:
        raise ValueError(
            "Credential type must include "
            "'VerifiableCredential'."
        )

    if "AcademicCredential" not in credential_types:
        raise ValueError(
            "Credential type must include "
            "'AcademicCredential'."
        )

    if not str(
        credential["issuer"]
    ).startswith("did:"):
        raise ValueError(
            "issuer must be represented as a DID."
        )

    subject = credential[
        "credentialSubject"
    ]

    if not isinstance(
        subject,
        dict,
    ):
        raise ValueError(
            "credentialSubject must be an object."
        )

    if "id" not in subject:
        raise ValueError(
            "credentialSubject must contain an id."
        )

    if not str(
        subject["id"]
    ).startswith("did:"):
        raise ValueError(
            "credentialSubject id must be a DID."
        )


# ============================================================
# File handling
# ============================================================

def load_workload(
    workload_path: Path,
) -> pd.DataFrame:
    """Load generated credential workload."""

    if not workload_path.exists():
        raise FileNotFoundError(
            f"Workload does not exist: {workload_path}"
        )

    df = pd.read_csv(
        workload_path
    )

    missing = (
        REQUIRED_WORKLOAD_FIELDS
        - set(df.columns)
    )

    if missing:
        raise ValueError(
            "Workload is missing required columns: "
            + ", ".join(sorted(missing))
        )

    return df


def save_credential(
    credential: dict[str, Any],
    output_path: Path,
) -> None:
    """Save a VC document as formatted JSON."""

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file_obj:

        json.dump(
            credential,
            file_obj,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Construct unsigned W3C VC 2.0 academic "
            "credential documents."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=(
            GENERATED_DATA_DIR
            / "academic_credentials_n1000_seed42.csv"
        ),
        help="Generated workload CSV.",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help=(
            "Number of credentials to construct. "
            "Default: 5"
        ),
    )

    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main() -> None:
    """Construct sample academic credentials."""

    args = parse_arguments()

    if args.count <= 0:
        raise ValueError(
            "--count must be greater than zero."
        )

    print("=" * 72)
    print("W3C VC 2.0 ACADEMIC CREDENTIAL BUILDER")
    print("=" * 72)

    print(
        f"\nInput workload:\n  {args.input}"
    )

    workload = load_workload(
        args.input
    )

    count = min(
        args.count,
        len(workload),
    )

    print(
        f"\nWorkload records: "
        f"{len(workload):,}"
    )

    print(
        f"Credentials to construct: "
        f"{count:,}"
    )

    # One fixed timestamp is deliberately used for the whole run.
    # This makes all credentials in a batch internally consistent.
    valid_from = datetime.now(
        timezone.utc
    ).replace(
        microsecond=0
    ).isoformat().replace(
        "+00:00",
        "Z",
    )

    output_directory = (
        CREDENTIAL_OUTPUT_DIR
        / f"sample_{count}"
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    created = 0

    for index in range(count):

        record = workload.iloc[
            index
        ].to_dict()

        credential = (
            build_academic_credential(
                record=record,
                valid_from=valid_from,
            )
        )

        validate_credential_structure(
            credential
        )

        output_path = (
            output_directory
            / (
                str(
                    record["credential_id"]
                )
                + ".json"
            )
        )

        save_credential(
            credential,
            output_path,
        )

        created += 1

    print("\n" + "=" * 72)
    print("VC CONSTRUCTION SUMMARY")
    print("=" * 72)

    print(
        f"Credentials created: {created:,}"
    )

    print(
        f"validFrom:           {valid_from}"
    )

    print(
        f"Output directory:\n  "
        f"{output_directory}"
    )

    sample_path = (
        output_directory
        / (
            str(
                workload.iloc[0][
                    "credential_id"
                ]
            )
            + ".json"
        )
    )

    print(
        f"\nExample credential:\n  "
        f"{sample_path}"
    )

    print(
        "\nIMPORTANT: These credentials are unsigned."
    )

    print(
        "Structural validation is not equivalent "
        "to W3C conformance or cryptographic verification."
    )

    print(
        "\nAcademic credential construction "
        "completed successfully."
    )


if __name__ == "__main__":
    main()