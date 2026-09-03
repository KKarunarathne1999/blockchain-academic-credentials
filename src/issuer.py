"""
Academic Credential Issuer
===========================

Creates W3C Data Integrity secured academic credentials using the
EdDSA `eddsa-jcs-2022` cryptosuite.

The implementation follows the main signing construction defined by
the W3C Data Integrity EdDSA Cryptosuites v1.0 Recommendation:

    unsecured credential
        ↓
    JCS canonicalization
        ↓
    SHA-256

    proof configuration
        ↓
    JCS canonicalization
        ↓
    SHA-256

        ↓
    concatenate hashes
        ↓
    Ed25519 signature
        ↓
    Multibase base58-btc proofValue

Research use only.
"""

from __future__ import annotations

import argparse
import copy
import json

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crypto_utils import (
    create_did_key,
    create_hash_data,
    create_verification_method,
    generate_ed25519_key_pair,
    load_private_key,
    load_public_key,
    multibase_base58btc_encode,
    sign_hash_data,
)


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

UNSIGNED_DIR = (
    PROJECT_ROOT
    / "credentials"
    / "unsigned"
    / "sample_5"
)

SIGNED_DIR = (
    PROJECT_ROOT
    / "credentials"
    / "signed"
)

KEY_DIR = (
    PROJECT_ROOT
    / "keys"
)

DEFAULT_ISSUER_NAME = (
    "research_academic_issuer"
)


# ============================================================
# Cryptosuite configuration
# ============================================================

PROOF_TYPE = "DataIntegrityProof"

CRYPTOSUITE = "eddsa-jcs-2022"

PROOF_PURPOSE = "assertionMethod"


# ============================================================
# JSON helpers
# ============================================================

def load_json(
    path: Path,
) -> dict[str, Any]:
    """Load JSON document."""

    with path.open(
        "r",
        encoding="utf-8",
    ) as file_obj:

        return json.load(
            file_obj
        )


def save_json(
    value: dict[str, Any],
    path: Path,
) -> None:
    """Save formatted JSON."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file_obj:

        json.dump(
            value,
            file_obj,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================
# Key management
# ============================================================

def ensure_issuer_keys(
    issuer_name: str,
) -> tuple[Path, Path]:
    """
    Return issuer key paths.

    Generate a new pair only if they do not
    already exist.
    """

    private_path = (
        KEY_DIR
        / f"{issuer_name}_private.pem"
    )

    public_path = (
        KEY_DIR
        / f"{issuer_name}_public.pem"
    )

    if (
        private_path.exists()
        and public_path.exists()
    ):

        print(
            "Using existing issuer key pair."
        )

        return (
            private_path,
            public_path,
        )

    if (
        private_path.exists()
        != public_path.exists()
    ):

        raise RuntimeError(
            "Incomplete issuer key pair detected. "
            "Both private and public key files "
            "must exist or both must be absent."
        )

    print(
        "Generating new Ed25519 issuer key pair..."
    )

    return generate_ed25519_key_pair(
        issuer_name
    )


# ============================================================
# Proof configuration
# ============================================================

def create_proof_configuration(
    credential: dict[str, Any],
    public_key,
    created: str,
) -> dict[str, Any]:
    """
    Construct an eddsa-jcs-2022 proof configuration.

    The credential's @context is copied into the proof
    configuration as required by the cryptosuite algorithm.
    """

    if "@context" not in credential:

        raise ValueError(
            "Credential does not contain @context."
        )

    return {
        "@context": copy.deepcopy(
            credential["@context"]
        ),

        "type": PROOF_TYPE,

        "cryptosuite": CRYPTOSUITE,

        "created": created,

        "verificationMethod": (
            create_verification_method(
                public_key
            )
        ),

        "proofPurpose": (
            PROOF_PURPOSE
        ),
    }


# ============================================================
# Credential signing
# ============================================================

def sign_credential(
    credential: dict[str, Any],
    private_key,
    public_key,
    created: str,
) -> dict[str, Any]:
    """
    Add a Data Integrity proof to an unsecured
    academic credential.
    """

    if "proof" in credential:

        raise ValueError(
            "Credential is already secured "
            "with a proof."
        )

    unsecured_document = copy.deepcopy(
        credential
    )

    proof_configuration = (
        create_proof_configuration(
            credential=unsecured_document,
            public_key=public_key,
            created=created,
        )
    )

    hash_data = create_hash_data(
        unsecured_document=unsecured_document,
        proof_configuration=proof_configuration,
    )

    signature = sign_hash_data(
        private_key=private_key,
        hash_data=hash_data,
    )

    proof = copy.deepcopy(
        proof_configuration
    )

    proof["proofValue"] = (
        multibase_base58btc_encode(
            signature
        )
    )

    secured_document = copy.deepcopy(
        unsecured_document
    )

    secured_document["proof"] = proof

    return secured_document


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Sign academic Verifiable Credentials "
            "using Ed25519 and eddsa-jcs-2022."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=UNSIGNED_DIR,
        help=(
            "Unsigned credential JSON file or "
            "directory containing JSON credentials."
        ),
    )

    parser.add_argument(
        "--issuer-name",
        default=DEFAULT_ISSUER_NAME,
        help=(
            "Local name used for issuer key files."
        ),
    )

    return parser.parse_args()


# ============================================================
# Input discovery
# ============================================================

def discover_credentials(
    path: Path,
) -> list[Path]:
    """Discover credential JSON files."""

    if path.is_file():

        if path.suffix.lower() != ".json":

            raise ValueError(
                "Input credential must be JSON."
            )

        return [
            path
        ]

    if not path.exists():

        raise FileNotFoundError(
            f"Input does not exist: {path}"
        )

    files = sorted(
        path.glob("*.json")
    )

    if not files:

        raise FileNotFoundError(
            f"No JSON credentials found in {path}"
        )

    return files


# ============================================================
# Main
# ============================================================

def main() -> None:
    """Sign academic credentials."""

    args = parse_arguments()

    print("=" * 72)
    print("W3C DATA INTEGRITY ACADEMIC CREDENTIAL ISSUER")
    print("=" * 72)

    private_path, public_path = (
        ensure_issuer_keys(
            args.issuer_name
        )
    )

    private_key = load_private_key(
        private_path
    )

    public_key = load_public_key(
        public_path
    )

    issuer_did = create_did_key(
        public_key
    )

    verification_method = (
        create_verification_method(
            public_key
        )
    )

    credential_paths = (
        discover_credentials(
            args.input
        )
    )

    print(
        f"\nCredentials discovered: "
        f"{len(credential_paths):,}"
    )

    print(
        f"\nSigning DID:\n  "
        f"{issuer_did}"
    )

    print(
        f"\nVerification method:\n  "
        f"{verification_method}"
    )

    created = datetime.now(
        timezone.utc
    ).replace(
        microsecond=0
    ).isoformat().replace(
        "+00:00",
        "Z",
    )

    print(
        f"\nProof creation time: {created}"
    )

    SIGNED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    signed_count = 0

    for credential_path in credential_paths:

        credential = load_json(
            credential_path
        )

        secured_credential = sign_credential(
            credential=credential,
            private_key=private_key,
            public_key=public_key,
            created=created,
        )

        output_path = (
            SIGNED_DIR
            / credential_path.name
        )

        save_json(
            secured_credential,
            output_path,
        )

        signed_count += 1

    print("\n" + "=" * 72)
    print("SIGNING SUMMARY")
    print("=" * 72)

    print(
        f"Credentials signed: {signed_count:,}"
    )

    print(
        f"Cryptosuite:        {CRYPTOSUITE}"
    )

    print(
        "Signature algorithm: Ed25519"
    )

    print(
        "Canonicalization:   RFC 8785 JCS"
    )

    print(
        f"Proof purpose:      {PROOF_PURPOSE}"
    )

    print(
        f"\nSigned credentials:\n  "
        f"{SIGNED_DIR}"
    )

    print(
        f"\nPublic key:\n  "
        f"{public_path}"
    )

    print(
        "\nPrivate key remains local and "
        "must never be committed to Git."
    )

    print(
        "\nCredential signing completed successfully."
    )


if __name__ == "__main__":
    main()