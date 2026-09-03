"""
Combined Academic Credential Trust Verifier
============================================

Combines two independent verification layers:

1. Cryptographic integrity verification
   - verifies the W3C Data Integrity proof
   - detects modification of signed credential claims

2. Blockchain issuer authorization
   - checks UKPRN
   - checks institutional issuer DID
   - checks authorised verification method
   - checks issuer active status

A credential is TRUSTED only when both layers succeed.

If cryptographic verification fails, blockchain authorization is
reported as NOT CHECKED because the trust pipeline stops before the
blockchain stage.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from blockchain_verifier import (
    check_issuer_authorization,
)
from verifier import (
    load_json,
    verify_credential,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_CREDENTIAL = (
    PROJECT_ROOT
    / "credentials"
    / "signed"
    / "CRED-000000000001.json"
)


def extract_trust_identity(
    credential: dict[str, Any],
) -> tuple[int, str, str]:
    """
    Extract the identity attributes used by the
    blockchain issuer registry.

    Returns:
        UKPRN,
        issuer DID,
        proof verification method
    """

    try:
        subject = credential[
            "credentialSubject"
        ]

        proof = credential[
            "proof"
        ]

        ukprn = int(
            subject[
                "issuerUkprn"
            ]
        )

        issuer_did = credential[
            "issuer"
        ]

        verification_method = proof[
            "verificationMethod"
        ]

    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise ValueError(
            "Credential does not contain "
            "a valid trust identity."
        ) from error

    if ukprn <= 0:
        raise ValueError(
            "Credential contains an invalid UKPRN."
        )

    if not isinstance(
        issuer_did,
        str,
    ) or not issuer_did.strip():
        raise ValueError(
            "Issuer DID is missing."
        )

    if not isinstance(
        verification_method,
        str,
    ) or not verification_method.strip():
        raise ValueError(
            "Verification method is missing."
        )

    return (
        ukprn,
        issuer_did,
        verification_method,
    )


def verify_trust(
    credential: dict[str, Any],
) -> dict[str, Any]:
    """
    Perform combined credential trust verification.

    Trust condition:

        cryptographic_valid == True
        AND
        blockchain_authorized == True

    blockchain_authorized is None when the blockchain
    stage is not reached.
    """

    result: dict[str, Any] = {
        "cryptographic_valid": False,
        "blockchain_authorized": None,
        "trusted": False,
        "reason": "",
    }

    # --------------------------------------------------
    # Stage 1:
    # Cryptographic integrity verification
    # --------------------------------------------------

    cryptographic_valid = (
        verify_credential(
            credential
        )
    )

    result[
        "cryptographic_valid"
    ] = cryptographic_valid

    if not cryptographic_valid:
        result["reason"] = (
            "Cryptographic verification failed."
        )

        return result

    # --------------------------------------------------
    # Stage 2:
    # Extract blockchain trust identity
    # --------------------------------------------------

    try:
        (
            ukprn,
            issuer_did,
            verification_method,
        ) = extract_trust_identity(
            credential
        )

    except ValueError as error:
        result["reason"] = str(
            error
        )

        return result

    # --------------------------------------------------
    # Stage 3:
    # Blockchain issuer authorization
    # --------------------------------------------------

    try:
        blockchain_authorized = (
            check_issuer_authorization(
                ukprn=ukprn,
                issuer_did=issuer_did,
                verification_method=(
                    verification_method
                ),
            )
        )

    except Exception as error:
        result["reason"] = (
            "Blockchain authorization "
            f"check failed: {error}"
        )

        return result

    result[
        "blockchain_authorized"
    ] = blockchain_authorized

    if not blockchain_authorized:
        result["reason"] = (
            "Issuer identity or signing key "
            "is not authorized on-chain."
        )

        result["ukprn"] = ukprn
        result["issuer_did"] = (
            issuer_did
        )
        result[
            "verification_method"
        ] = verification_method

        return result

    # --------------------------------------------------
    # Final trust decision
    # --------------------------------------------------

    result["trusted"] = True

    result["reason"] = (
        "Credential integrity verified and "
        "issuer is authorized on-chain."
    )

    result["ukprn"] = ukprn

    result["issuer_did"] = (
        issuer_did
    )

    result[
        "verification_method"
    ] = verification_method

    return result


def blockchain_status_text(
    blockchain_authorized: bool | None,
) -> str:
    """
    Convert blockchain authorization state into
    a human-readable status.
    """

    if blockchain_authorized is None:
        return "NOT CHECKED"

    if blockchain_authorized:
        return "AUTHORIZED"

    return "NOT AUTHORIZED"


def print_result(
    credential_path: Path,
    result: dict[str, Any],
) -> None:
    """
    Print a human-readable trust decision.
    """

    print(
        "Credential:",
        credential_path,
    )

    print(
        "\nCOMBINED TRUST VERIFICATION"
    )

    print(
        "Cryptographic integrity:",
        (
            "PASS"
            if result[
                "cryptographic_valid"
            ]
            else "FAIL"
        ),
    )

    print(
        "Blockchain authorization:",
        blockchain_status_text(
            result[
                "blockchain_authorized"
            ]
        ),
    )

    print(
        "\nFinal trust decision:",
        (
            "TRUSTED"
            if result["trusted"]
            else "REJECTED"
        ),
    )

    print(
        "Reason:",
        result["reason"],
    )

    if "ukprn" in result:
        print(
            "\nTRUST IDENTITY"
        )

        print(
            "UKPRN:",
            result["ukprn"],
        )

        print(
            "Issuer DID:",
            result["issuer_did"],
        )

        print(
            "Verification method:",
            result[
                "verification_method"
            ],
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Verify academic credential "
            "cryptographic integrity and "
            "blockchain issuer authorization."
        )
    )

    parser.add_argument(
        "--credential",
        type=Path,
        default=DEFAULT_CREDENTIAL,
        help=(
            "Path to signed credential JSON."
        ),
    )

    args = parser.parse_args()

    credential = load_json(
        args.credential
    )

    result = verify_trust(
        credential
    )

    print_result(
        args.credential,
        result,
    )


if __name__ == "__main__":
    main()