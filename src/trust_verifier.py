"""
Combined Academic Credential Trust Verifier
============================================

Combines three independent verification layers:

1. Cryptographic integrity verification
   - verifies the W3C Data Integrity proof
   - detects modification of signed credential claims

2. Blockchain issuer authorization
   - checks UKPRN
   - checks institutional issuer DID
   - checks authorised verification method
   - checks issuer active status

3. Blockchain credential status
   - checks whether the credential is registered
   - checks whether the credential has been revoked
   - accepts only registered and non-revoked credentials

A credential is TRUSTED only when all three layers succeed.

Verification follows a fail-closed pipeline. Later stages are
reported as NOT CHECKED when an earlier trust requirement fails.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from blockchain_verifier import (
    check_issuer_authorization,
)
from credential_status_verifier import (
    get_credential_status,
    is_credential_registered,
)
from verifier import (
    load_json,
    verify_credential,
)


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

DEFAULT_CREDENTIAL = (
    PROJECT_ROOT
    / "credentials"
    / "signed"
    / "CRED-000000000001.json"
)


# ============================================================
# Trust identity extraction
# ============================================================

def extract_trust_identity(
    credential: dict[str, Any],
) -> tuple[
    int,
    str,
    str,
    str,
]:
    """
    Extract attributes required by the blockchain
    trust layers.

    Returns:
        UKPRN,
        issuer DID,
        proof verification method,
        credential ID
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

        credential_id = credential[
            "id"
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

    if (
        not isinstance(
            issuer_did,
            str,
        )
        or not issuer_did.strip()
    ):
        raise ValueError(
            "Issuer DID is missing."
        )

    if (
        not isinstance(
            verification_method,
            str,
        )
        or not verification_method.strip()
    ):
        raise ValueError(
            "Verification method is missing."
        )

    if (
        not isinstance(
            credential_id,
            str,
        )
        or not credential_id.strip()
    ):
        raise ValueError(
            "Credential ID is missing."
        )

    return (
        ukprn,
        issuer_did,
        verification_method,
        credential_id,
    )


# ============================================================
# Combined trust verification
# ============================================================

def verify_trust(
    credential: dict[str, Any],
) -> dict[str, Any]:
    """
    Perform combined credential trust verification.

    Trust condition:

        cryptographic_valid == True

        AND

        blockchain_authorized == True

        AND

        credential_registered == True

        AND

        credential_revoked == False

        AND

        credential_status_valid == True

    Later verification stages remain None when
    an earlier stage fails.
    """

    result: dict[str, Any] = {

        "cryptographic_valid": False,

        "blockchain_authorized": None,

        "credential_registered": None,

        "credential_revoked": None,

        "credential_status_valid": None,

        "trusted": False,

        "reason": "",
    }

    # --------------------------------------------------------
    # Stage 1:
    # Cryptographic integrity verification
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Stage 2:
    # Extract trust identity
    # --------------------------------------------------------

    try:

        (
            ukprn,
            issuer_did,
            verification_method,
            credential_id,
        ) = extract_trust_identity(
            credential
        )

    except ValueError as error:

        result["reason"] = str(
            error
        )

        return result

    result[
        "ukprn"
    ] = ukprn

    result[
        "issuer_did"
    ] = issuer_did

    result[
        "verification_method"
    ] = verification_method

    result[
        "credential_id"
    ] = credential_id

    # --------------------------------------------------------
    # Stage 3:
    # Blockchain issuer authorization
    # --------------------------------------------------------

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

        return result

    # --------------------------------------------------------
    # Stage 4:
    # Credential registration check
    # --------------------------------------------------------

    try:

        registered = (
            is_credential_registered(
                credential_id
            )
        )

    except Exception as error:

        result["reason"] = (
            "Credential status registration "
            f"check failed: {error}"
        )

        return result

    result[
        "credential_registered"
    ] = registered

    if not registered:

        result[
            "credential_revoked"
        ] = None

        result[
            "credential_status_valid"
        ] = False

        result["reason"] = (
            "Credential is not registered "
            "in the blockchain status registry."
        )

        return result

    # --------------------------------------------------------
    # Stage 5:
    # Credential revocation/status check
    # --------------------------------------------------------

    try:

        status = (
            get_credential_status(
                credential_id
            )
        )

    except Exception as error:

        result["reason"] = (
            "Credential status check failed: "
            f"{error}"
        )

        return result

    revoked = bool(
        status[
            "revoked"
        ]
    )

    status_valid = (
        bool(
            status[
                "registered"
            ]
        )
        and not revoked
    )

    result[
        "credential_registered"
    ] = bool(
        status[
            "registered"
        ]
    )

    result[
        "credential_revoked"
    ] = revoked

    result[
        "credential_status_valid"
    ] = status_valid

    result[
        "credential_hash"
    ] = status[
        "credential_hash"
    ]

    result[
        "credential_registered_at"
    ] = status[
        "registered_at"
    ]

    result[
        "credential_revoked_at"
    ] = status[
        "revoked_at"
    ]

    if revoked:

        result["reason"] = (
            "Credential has been revoked "
            "in the blockchain status registry."
        )

        return result

    if not status_valid:

        result["reason"] = (
            "Credential blockchain status "
            "is not valid."
        )

        return result

    # --------------------------------------------------------
    # Final trust decision
    # --------------------------------------------------------

    result[
        "trusted"
    ] = True

    result[
        "reason"
    ] = (
        "Credential integrity verified, "
        "issuer is authorized on-chain, "
        "and credential status is active."
    )

    return result


# ============================================================
# Human-readable status helpers
# ============================================================

def blockchain_status_text(
    blockchain_authorized: bool | None,
) -> str:
    """
    Convert issuer authorization state into
    human-readable text.
    """

    if blockchain_authorized is None:
        return "NOT CHECKED"

    if blockchain_authorized:
        return "AUTHORIZED"

    return "NOT AUTHORIZED"


def credential_registration_text(
    registered: bool | None,
) -> str:
    """
    Convert credential registration state into
    human-readable text.
    """

    if registered is None:
        return "NOT CHECKED"

    if registered:
        return "REGISTERED"

    return "NOT REGISTERED"


def credential_revocation_text(
    revoked: bool | None,
) -> str:
    """
    Convert credential revocation state into
    human-readable text.
    """

    if revoked is None:
        return "NOT CHECKED"

    if revoked:
        return "REVOKED"

    return "ACTIVE"


def credential_validity_text(
    valid: bool | None,
) -> str:
    """
    Convert credential validity state into
    human-readable text.
    """

    if valid is None:
        return "NOT CHECKED"

    if valid:
        return "VALID"

    return "INVALID"


# ============================================================
# Output
# ============================================================

def print_result(
    credential_path: Path,
    result: dict[str, Any],
) -> None:
    """
    Print a human-readable combined trust decision.
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
        "Issuer authorization:",
        blockchain_status_text(
            result[
                "blockchain_authorized"
            ]
        ),
    )

    print(
        "Credential registration:",
        credential_registration_text(
            result[
                "credential_registered"
            ]
        ),
    )

    print(
        "Credential revocation:",
        credential_revocation_text(
            result[
                "credential_revoked"
            ]
        ),
    )

    print(
        "Credential status:",
        credential_validity_text(
            result[
                "credential_status_valid"
            ]
        ),
    )

    print(
        "\nFinal trust decision:",
        (
            "TRUSTED"
            if result[
                "trusted"
            ]
            else "REJECTED"
        ),
    )

    print(
        "Reason:",
        result[
            "reason"
        ],
    )

    if (
        "credential_id"
        in result
    ):

        print(
            "\nTRUST IDENTITY"
        )

        print(
            "Credential ID:",
            result[
                "credential_id"
            ],
        )

        print(
            "UKPRN:",
            result[
                "ukprn"
            ],
        )

        print(
            "Issuer DID:",
            result[
                "issuer_did"
            ],
        )

        print(
            "Verification method:",
            result[
                "verification_method"
            ],
        )

    if (
        "credential_hash"
        in result
    ):

        print(
            "\nON-CHAIN CREDENTIAL STATUS"
        )

        print(
            "Credential hash:",
            result[
                "credential_hash"
            ],
        )

        print(
            "Registered at:",
            result[
                "credential_registered_at"
            ],
        )

        print(
            "Revoked at:",
            result[
                "credential_revoked_at"
            ],
        )


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Verify academic credential integrity, "
            "issuer authorization and blockchain "
            "credential status."
        )
    )

    parser.add_argument(
        "--credential",
        type=Path,
        default=DEFAULT_CREDENTIAL,
        help=(
            "Path to the secured academic "
            "credential JSON file."
        ),
    )

    return parser.parse_args()


def main() -> None:
    """
    Run combined trust verification.
    """

    args = parse_arguments()

    credential_path = (
        args.credential
        .expanduser()
        .resolve()
    )

    if not credential_path.exists():
        raise FileNotFoundError(
            "Credential file not found: "
            f"{credential_path}"
        )

    credential = load_json(
        credential_path
    )

    result = verify_trust(
        credential
    )

    print_result(
        credential_path=credential_path,
        result=result,
    )


if __name__ == "__main__":
    main()