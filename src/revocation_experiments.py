"""
Credential Revocation Experiments
=================================

Evaluates credential-level revocation while keeping:

- cryptographic integrity valid
- issuer authorization valid

The experiment demonstrates that a credential can
remain cryptographically valid and originate from an
authorised issuer, yet still be rejected because its
credential-level blockchain status is revoked.

The registry state is inspected before execution.
Because the current status contract does not support
un-revocation, this experiment should only be run when
you are ready to permanently revoke the sample
credential on the current local Hardhat chain.

Research prototype only.
"""

from __future__ import annotations

from typing import Any

from blockchain_verifier import (
    check_issuer_authorization,
)
from credential_status_verifier import (
    STATUS_REGISTRY_ADDRESS,
    connect_to_status_blockchain,
    credential_id_to_hash,
    get_status_registry_contract,
)
from trust_verifier import (
    DEFAULT_CREDENTIAL,
    verify_trust,
)
from verifier import (
    load_json,
    verify_credential,
)


def print_result(
    name: str,
    result: dict[str, Any],
) -> None:
    """
    Display one experiment result.
    """

    print(
        f"\n{name}"
    )

    print(
        "-" * len(name)
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

    blockchain_status = result[
        "blockchain_authorized"
    ]

    if blockchain_status is None:
        blockchain_text = (
            "NOT CHECKED"
        )
    elif blockchain_status:
        blockchain_text = (
            "AUTHORIZED"
        )
    else:
        blockchain_text = (
            "NOT AUTHORIZED"
        )

    print(
        "Issuer authorization:",
        blockchain_text,
    )

    registered = result[
        "credential_registered"
    ]

    print(
        "Credential registered:",
        registered,
    )

    revoked = result[
        "credential_revoked"
    ]

    print(
        "Credential revoked:",
        revoked,
    )

    print(
        "Credential status valid:",
        result[
            "credential_status_valid"
        ],
    )

    print(
        "Final decision:",
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


def main() -> None:
    """
    Run controlled credential revocation experiment.
    """

    credential = load_json(
        DEFAULT_CREDENTIAL
    )

    credential_id = credential[
        "id"
    ]

    subject = credential[
        "credentialSubject"
    ]

    ukprn = int(
        subject[
            "issuerUkprn"
        ]
    )

    issuer_did = credential[
        "issuer"
    ]

    verification_method = credential[
        "proof"
    ][
        "verificationMethod"
    ]

    web3 = (
        connect_to_status_blockchain()
    )

    registry = (
        get_status_registry_contract(
            web3
        )
    )

    credential_hash = (
        credential_id_to_hash(
            credential_id
        )
    )

    print(
        "CREDENTIAL REVOCATION EXPERIMENT"
    )

    print(
        "\nChain ID:",
        web3.eth.chain_id,
    )

    print(
        "CredentialStatusRegistry:",
        STATUS_REGISTRY_ADDRESS,
    )

    print(
        "Credential ID:",
        credential_id,
    )

    print(
        "Credential hash:",
        "0x" + credential_hash.hex(),
    )

    # --------------------------------------------------------
    # Confirm cryptographic and issuer state independently
    # --------------------------------------------------------

    crypto_valid = (
        verify_credential(
            credential
        )
    )

    issuer_authorized = (
        check_issuer_authorization(
            ukprn=ukprn,
            issuer_did=issuer_did,
            verification_method=(
                verification_method
            ),
        )
    )

    if not crypto_valid:
        raise RuntimeError(
            "Baseline credential is not "
            "cryptographically valid."
        )

    if not issuer_authorized:
        raise RuntimeError(
            "Baseline issuer is not authorized."
        )

    # --------------------------------------------------------
    # Read current credential status
    # --------------------------------------------------------

    registered = (
        registry.functions
        .isCredentialRegistered(
            credential_hash
        )
        .call()
    )

    revoked = (
        registry.functions
        .isCredentialRevoked(
            credential_hash
        )
        .call()
    )

    if not registered:
        raise RuntimeError(
            "Credential must be registered "
            "before running this experiment."
        )

    if revoked:
        raise RuntimeError(
            "Credential is already revoked. "
            "Restart/redeploy the local chain "
            "to repeat this experiment."
        )

    # --------------------------------------------------------
    # Scenario 1:
    # Active credential
    # --------------------------------------------------------

    before = verify_trust(
        credential
    )

    print_result(
        "SCENARIO 1 - ACTIVE CREDENTIAL",
        before,
    )

    if not before[
        "trusted"
    ]:
        raise RuntimeError(
            "Baseline credential should be trusted "
            "before revocation."
        )

    # --------------------------------------------------------
    # Revoke credential
    # --------------------------------------------------------

    owner = (
        web3.eth.accounts[
            0
        ]
    )

    contract_owner = (
        registry.functions
        .owner()
        .call()
    )

    if (
        owner.lower()
        != contract_owner.lower()
    ):
        raise RuntimeError(
            "Local account is not the "
            "CredentialStatusRegistry owner."
        )

    print(
        "\nRevoking credential..."
    )

    transaction_hash = (
        registry.functions
        .revokeCredential(
            credential_hash
        )
        .transact(
            {
                "from": owner
            }
        )
    )

    receipt = (
        web3.eth
        .wait_for_transaction_receipt(
            transaction_hash
        )
    )

    if receipt.status != 1:
        raise RuntimeError(
            "Credential revocation "
            "transaction failed."
        )

    print(
        "Revocation transaction:",
        transaction_hash.hex(),
    )

    # --------------------------------------------------------
    # Scenario 2:
    # Same credential after revocation
    # --------------------------------------------------------

    after = verify_trust(
        credential
    )

    print_result(
        "SCENARIO 2 - REVOKED CREDENTIAL",
        after,
    )

    expected = (
        after[
            "cryptographic_valid"
        ]
        is True
        and after[
            "blockchain_authorized"
        ]
        is True
        and after[
            "credential_registered"
        ]
        is True
        and after[
            "credential_revoked"
        ]
        is True
        and after[
            "credential_status_valid"
        ]
        is False
        and after[
            "trusted"
        ]
        is False
    )

    print(
        "\nEXPERIMENT RESULT"
    )

    print(
        "Expected outcome:",
        (
            "PASS"
            if expected
            else "FAIL"
        ),
    )

    if expected:

        print(
            "\nInterpretation:"
        )

        print(
            "The credential remains cryptographically "
            "valid and the issuer remains authorized, "
            "but credential-level revocation causes the "
            "final trust decision to be REJECTED."
        )


if __name__ == "__main__":
    main()