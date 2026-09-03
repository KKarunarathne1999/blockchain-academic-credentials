"""
Academic Credential Verifier
==============================

Verifies W3C Data Integrity secured academic credentials using the
eddsa-jcs-2022 cryptosuite.

The verifier:

1. extracts the Data Integrity proof
2. removes proofValue
3. reconstructs the unsecured document
4. canonicalizes proof configuration and document using RFC 8785 JCS
5. recreates the SHA-256 hash data
6. derives the Ed25519 public key from verificationMethod
7. verifies the Ed25519 signature

The module also supports controlled tampering experiments for evaluating
credential integrity.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from crypto_utils import (
    create_hash_data,
    multibase_base58btc_decode,
    public_key_from_multibase,
    verify_hash_data,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_CREDENTIAL = (
    PROJECT_ROOT
    / "credentials"
    / "signed"
    / "CRED-000000000001.json"
)

EXPECTED_PROOF_TYPE = "DataIntegrityProof"
EXPECTED_CRYPTOSUITE = "eddsa-jcs-2022"
EXPECTED_PROOF_PURPOSE = "assertionMethod"


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON credential."""

    if not path.exists():
        raise FileNotFoundError(
            f"Credential does not exist: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file_obj:
        return json.load(file_obj)


def validate_proof_structure(
    proof: dict[str, Any],
) -> None:
    """Perform basic proof structure validation."""

    required = {
        "type",
        "cryptosuite",
        "verificationMethod",
        "proofPurpose",
        "proofValue",
    }

    missing = required - set(proof)

    if missing:
        raise ValueError(
            "Proof is missing fields: "
            + ", ".join(sorted(missing))
        )

    if proof["type"] != EXPECTED_PROOF_TYPE:
        raise ValueError(
            "Unsupported proof type."
        )

    if proof["cryptosuite"] != EXPECTED_CRYPTOSUITE:
        raise ValueError(
            "Unsupported cryptosuite."
        )

    if proof["proofPurpose"] != EXPECTED_PROOF_PURPOSE:
        raise ValueError(
            "Unexpected proof purpose."
        )


def extract_public_key_from_verification_method(
    verification_method: str,
):
    """
    Extract the Ed25519 public key from a did:key
    verification method.

    Expected form:

        did:key:<multikey>#<multikey>
    """

    if not verification_method.startswith("did:key:"):
        raise ValueError(
            "Only did:key verification methods "
            "are supported in this prototype."
        )

    did_part, separator, fragment = (
        verification_method.partition("#")
    )

    if not separator or not fragment:
        raise ValueError(
            "verificationMethod must contain "
            "a DID URL fragment."
        )

    multikey = did_part.removeprefix(
        "did:key:"
    )

    if fragment != multikey:
        raise ValueError(
            "did:key verification method fragment "
            "does not match the multikey."
        )

    return public_key_from_multibase(
        multikey
    )


def verify_credential(
    secured_document: dict[str, Any],
) -> bool:
    """
    Verify an eddsa-jcs-2022 Data Integrity proof.
    """

    if "proof" not in secured_document:
        return False

    proof = copy.deepcopy(
        secured_document["proof"]
    )

    try:
        validate_proof_structure(proof)

        proof_value = proof.pop(
            "proofValue"
        )

        if "@context" in proof:
            document_context = (
                secured_document.get("@context")
            )

            proof_context = proof["@context"]

            if not isinstance(
                document_context,
                list,
            ):
                return False

            if not isinstance(
                proof_context,
                list,
            ):
                return False

            if (
                document_context[
                    :len(proof_context)
                ]
                != proof_context
            ):
                return False

        unsecured_document = copy.deepcopy(
            secured_document
        )

        unsecured_document.pop(
            "proof",
            None,
        )

        if "@context" in proof:
            unsecured_document["@context"] = (
                copy.deepcopy(
                    proof["@context"]
                )
            )

        signature = (
            multibase_base58btc_decode(
                proof_value
            )
        )

        if len(signature) != 64:
            return False

        public_key = (
            extract_public_key_from_verification_method(
                proof["verificationMethod"]
            )
        )

        hash_data = create_hash_data(
            unsecured_document=unsecured_document,
            proof_configuration=proof,
        )

        return verify_hash_data(
            public_key=public_key,
            signature=signature,
            hash_data=hash_data,
        )

    except (
        ValueError,
        TypeError,
        KeyError,
    ):
        return False


def create_tampered_copy(
    credential: dict[str, Any],
    attack: str,
) -> dict[str, Any]:
    """Create controlled credential tampering scenarios."""

    tampered = copy.deepcopy(
        credential
    )

    if attack == "programme":

        tampered[
            "credentialSubject"
        ][
            "programme"
        ] = "MSc Quantum Computing"

    elif attack == "classification":

        tampered[
            "credentialSubject"
        ][
            "classification"
        ] = "First Class"

    elif attack == "holder":

        tampered[
            "credentialSubject"
        ][
            "id"
        ] = (
            "did:example:holder:"
            "999999999999"
        )

    elif attack == "issuer":

        tampered[
            "issuer"
        ] = (
            "did:example:issuer:"
            "ukprn-99999999"
        )

    elif attack == "graduation-year":

        tampered[
            "credentialSubject"
        ][
            "graduationYear"
        ] = 2030

    else:

        raise ValueError(
            f"Unknown attack: {attack}"
        )

    return tampered


def run_integrity_tests(
    credential: dict[str, Any],
) -> dict[str, bool]:
    """
    Run baseline and tampering verification tests.
    """

    results = {
        "original": (
            verify_credential(
                credential
            )
        )
    }

    attacks = [
        "programme",
        "classification",
        "holder",
        "issuer",
        "graduation-year",
    ]

    for attack in attacks:

        tampered = create_tampered_copy(
            credential,
            attack,
        )

        results[attack] = (
            verify_credential(
                tampered
            )
        )

    return results


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Verify eddsa-jcs-2022 "
            "academic credentials."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_CREDENTIAL,
        help="Signed credential JSON file.",
    )

    parser.add_argument(
        "--tamper-tests",
        action="store_true",
        help=(
            "Run controlled credential "
            "tampering tests."
        ),
    )

    return parser.parse_args()


def main() -> None:
    """Run credential verification."""

    args = parse_arguments()

    print("=" * 72)
    print("ACADEMIC CREDENTIAL CRYPTOGRAPHIC VERIFIER")
    print("=" * 72)

    print(
        f"\nCredential:\n  {args.input}"
    )

    credential = load_json(
        args.input
    )

    verified = verify_credential(
        credential
    )

    print(
        "\nCryptographic verification:"
    )

    print(
        "  PASS"
        if verified
        else "  FAIL"
    )

    if args.tamper_tests:

        print("\n" + "=" * 72)
        print("CONTROLLED TAMPERING TESTS")
        print("=" * 72)

        results = run_integrity_tests(
            credential
        )

        for test_name, result in results.items():

            if test_name == "original":
                expected = True
            else:
                expected = False

            experiment_passed = (
                result == expected
            )

            verification_text = (
                "VALID"
                if result
                else "INVALID"
            )

            outcome_text = (
                "PASS"
                if experiment_passed
                else "FAIL"
            )

            print(
                f"{test_name:<20}"
                f"{verification_text:<10}"
                f"{outcome_text}"
            )

        all_expected = (
            results["original"]
            and all(
                not result
                for name, result
                in results.items()
                if name != "original"
            )
        )

        print("\nIntegrity experiment:")

        print(
            "  PASS"
            if all_expected
            else "  FAIL"
        )


if __name__ == "__main__":
    main()