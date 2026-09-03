"""
Blockchain-Specific Trust Experiments
=====================================

Evaluates scenarios where a credential remains
cryptographically valid but blockchain authorization
changes.

These experiments demonstrate the contribution of
the blockchain issuer registry beyond signature
verification alone.

Scenarios:

1. authorised issuer
2. deactivated issuer
3. reactivated issuer
4. old credential after key rotation
5. new credential after key rotation
6. original key restored
7. cryptographically valid but unauthorised key

The registry is restored to its original state at
the end of the experiment.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

from blockchain_verifier import (

    REGISTRY_ADDRESS,

    connect_to_blockchain,

    get_registry_contract,

)

from issuer import (

    ensure_issuer_keys,

    load_private_key,

    load_public_key,

    sign_credential,

)

from trust_verifier import (

    DEFAULT_CREDENTIAL,

    blockchain_status_text,

    verify_trust,

)

from verifier import load_json

ROGUE_ISSUER_NAME = (

    "research_rogue_issuer"

)


def run_trust_scenario(
    name: str,
    credential: dict[str, Any],
    expected_crypto: bool,
    expected_blockchain: bool | None,
    expected_trusted: bool,
) -> dict[str, Any]:
    """
    Run one combined trust verification scenario.
    """

    result = verify_trust(
        credential
    )

    actual_crypto = result[
        "cryptographic_valid"
    ]

    actual_blockchain = result[
        "blockchain_authorized"
    ]

    actual_trusted = result[
        "trusted"
    ]

    passed = (
        actual_crypto
        == expected_crypto
        and actual_blockchain
        == expected_blockchain
        and actual_trusted
        == expected_trusted
    )

    return {
        "scenario": name,

        "crypto": (
            "PASS"
            if actual_crypto
            else "FAIL"
        ),

        "blockchain": (
            blockchain_status_text(
                actual_blockchain
            )
        ),

        "decision": (
            "TRUSTED"
            if actual_trusted
            else "REJECTED"
        ),

        "expected": (
            "TRUSTED"
            if expected_trusted
            else "REJECTED"
        ),

        "test": (
            "PASS"
            if passed
            else "FAIL"
        ),

        "reason": result[
            "reason"
        ],
    }


def transaction_wait(
    web3,
    transaction_hash,
) -> None:
    """
    Wait for a Web3 transaction to be mined.

    Web3.py's transact() returns a transaction hash,
    so wait_for_transaction_receipt() is used to
    obtain the final receipt.
    """

    receipt = (
        web3.eth.wait_for_transaction_receipt(
            transaction_hash
        )
    )

    if receipt.status != 1:
        raise RuntimeError(
            "Blockchain transaction failed."
        )


def get_registry():
    """
    Connect to the local blockchain and return the
    IssuerRegistry contract.
    """

    web3 = connect_to_blockchain()

    registry = get_registry_contract(
        web3
    )

    return (
        web3,
        registry,
    )


def create_rogue_credential(
    original_signed: dict[str, Any],
) -> tuple[
    dict[str, Any],
    str,
]:
    """
    Create a credential containing the same claims as
    the valid credential but signed by a different
    Ed25519 key.

    The credential itself remains cryptographically
    valid.

    Whether it is trusted depends on whether that
    verification method is authorised by the
    blockchain registry.
    """

    unsigned = copy.deepcopy(
        original_signed
    )

    unsigned.pop(
        "proof",
        None,
    )

    (
        rogue_private_path,
        rogue_public_path,
    ) = ensure_issuer_keys(
        ROGUE_ISSUER_NAME
    )

    rogue_private_key = (
        load_private_key(
            rogue_private_path
        )
    )

    rogue_public_key = (
        load_public_key(
            rogue_public_path
        )
    )

    created = (
        datetime.now(
            timezone.utc
        )
        .replace(
            microsecond=0
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )

    rogue_credential = (
        sign_credential(
            credential=unsigned,
            private_key=(
                rogue_private_key
            ),
            public_key=(
                rogue_public_key
            ),
            created=created,
        )
    )

    rogue_verification_method = (
        rogue_credential[
            "proof"
        ][
            "verificationMethod"
        ]
    )

    return (
        rogue_credential,
        rogue_verification_method,
    )


def print_results(
    results: list[
        dict[str, Any]
    ],
) -> None:
    """
    Display the experiment results.
    """

    print(
        "\nBLOCKCHAIN-SPECIFIC TRUST EXPERIMENTS\n"
    )

    print(
        f"{'Scenario':<34}"
        f"{'Crypto':<10}"
        f"{'Blockchain':<18}"
        f"{'Decision':<12}"
        f"{'Expected':<12}"
        f"{'Test':<8}"
    )

    print(
        "-" * 94
    )

    for result in results:
        print(
            f"{result['scenario']:<34}"
            f"{result['crypto']:<10}"
            f"{result['blockchain']:<18}"
            f"{result['decision']:<12}"
            f"{result['expected']:<12}"
            f"{result['test']:<8}"
        )

    passed = sum(
        1
        for result in results
        if result[
            "test"
        ] == "PASS"
    )

    total = len(
        results
    )

    print(
        "\nExperiments passed:",
        f"{passed}/{total}",
    )

    print(
        "\nSCENARIO DETAILS"
    )

    for result in results:
        print(
            f"\n{result['scenario']}:"
        )

        print(
            "  Reason:",
            result[
                "reason"
            ],
        )


def main() -> None:
    """
    Execute blockchain-state trust experiments.
    """

    original = load_json(
        DEFAULT_CREDENTIAL
    )

    ukprn = int(
        original[
            "credentialSubject"
        ][
            "issuerUkprn"
        ]
    )

    issuer_did = original[
        "issuer"
    ]

    original_method = original[
        "proof"
    ][
        "verificationMethod"
    ]

    web3, registry = (
        get_registry()
    )

    print(
        "Connected to blockchain:",
        web3.is_connected(),
    )

    print(
        "Chain ID:",
        web3.eth.chain_id,
    )

    print(
        "IssuerRegistry:",
        REGISTRY_ADDRESS,
    )

    print(
        "UKPRN:",
        ukprn,
    )

    print(
        "Issuer DID:",
        issuer_did,
    )

    print(
        "Original verification method:",
        original_method,
    )

    results: list[
        dict[str, Any]
    ] = []

    try:

        # ==================================================
        # Scenario 1
        #
        # Baseline:
        # valid credential + authorised issuer/key.
        # ==================================================

        results.append(
            run_trust_scenario(
                name="authorised-issuer",
                credential=(
                    copy.deepcopy(
                        original
                    )
                ),
                expected_crypto=True,
                expected_blockchain=True,
                expected_trusted=True,
            )
        )

        # ==================================================
        # Scenario 2
        #
        # Deactivate issuer.
        #
        # The credential remains cryptographically valid,
        # but blockchain authorization must fail.
        # ==================================================

        tx_hash = (
            registry.functions
            .deactivateIssuer(
                ukprn
            )
            .transact(
                {
                    "from":
                    web3.eth.accounts[
                        0
                    ]
                }
            )
        )

        transaction_wait(
            web3,
            tx_hash,
        )

        results.append(
            run_trust_scenario(
                name="deactivated-issuer",
                credential=(
                    copy.deepcopy(
                        original
                    )
                ),
                expected_crypto=True,
                expected_blockchain=False,
                expected_trusted=False,
            )
        )

        # ==================================================
        # Scenario 3
        #
        # Reactivate issuer.
        # ==================================================

        tx_hash = (
            registry.functions
            .reactivateIssuer(
                ukprn
            )
            .transact(
                {
                    "from":
                    web3.eth.accounts[
                        0
                    ]
                }
            )
        )

        transaction_wait(
            web3,
            tx_hash,
        )

        results.append(
            run_trust_scenario(
                name="reactivated-issuer",
                credential=(
                    copy.deepcopy(
                        original
                    )
                ),
                expected_crypto=True,
                expected_blockchain=True,
                expected_trusted=True,
            )
        )

        # ==================================================
        # Create second Ed25519 key pair and generate a
        # cryptographically valid credential using it.
        # ==================================================

        (
            rogue_credential,
            rogue_method,
        ) = create_rogue_credential(
            original
        )

        print(
            "\nExperimental secondary verification method:",
            rogue_method,
        )

        # ==================================================
        # Scenario 4
        #
        # Rotate blockchain authorization to the new key.
        #
        # The old credential's signature still validates,
        # but its signing key is no longer authorised.
        # ==================================================

        tx_hash = (
            registry.functions
            .updateVerificationMethod(
                ukprn,
                rogue_method,
            )
            .transact(
                {
                    "from":
                    web3.eth.accounts[
                        0
                    ]
                }
            )
        )

        transaction_wait(
            web3,
            tx_hash,
        )

        results.append(
            run_trust_scenario(
                name="old-key-after-rotation",
                credential=(
                    copy.deepcopy(
                        original
                    )
                ),
                expected_crypto=True,
                expected_blockchain=False,
                expected_trusted=False,
            )
        )

        # ==================================================
        # Scenario 5
        #
        # The newly signed credential uses the now
        # authorised replacement verification method.
        # ==================================================

        results.append(
            run_trust_scenario(
                name="new-key-after-rotation",
                credential=(
                    copy.deepcopy(
                        rogue_credential
                    )
                ),
                expected_crypto=True,
                expected_blockchain=True,
                expected_trusted=True,
            )
        )

        # ==================================================
        # Restore original signing key authorization.
        # ==================================================

        tx_hash = (
            registry.functions
            .updateVerificationMethod(
                ukprn,
                original_method,
            )
            .transact(
                {
                    "from":
                    web3.eth.accounts[
                        0
                    ]
                }
            )
        )

        transaction_wait(
            web3,
            tx_hash,
        )

        # ==================================================
        # Scenario 6
        #
        # Original credential becomes trusted again.
        # ==================================================

        results.append(
            run_trust_scenario(
                name="original-key-restored",
                credential=(
                    copy.deepcopy(
                        original
                    )
                ),
                expected_crypto=True,
                expected_blockchain=True,
                expected_trusted=True,
            )
        )

        # ==================================================
        # Scenario 7
        #
        # Credential signed by the secondary key remains
        # cryptographically valid, but after restoring the
        # original registry key it is no longer authorised.
        #
        # This demonstrates why signature validity alone
        # does not establish institutional authorization.
        # ==================================================

        results.append(
            run_trust_scenario(
                name=(
                    "valid-but-unauthorised-key"
                ),
                credential=(
                    copy.deepcopy(
                        rogue_credential
                    )
                ),
                expected_crypto=True,
                expected_blockchain=False,
                expected_trusted=False,
            )
        )

    finally:

        # ==================================================
        # Registry restoration
        #
        # Return the issuer record to:
        #
        # active = True
        # verificationMethod = original_method
        #
        # even if an experiment raises an exception.
        # ==================================================

        try:

            record = (
                registry.functions
                .getIssuer(
                    ukprn
                )
                .call()
            )

            current_method = (
                record[2]
            )

            active = (
                record[3]
            )

            if (
                current_method
                != original_method
            ):

                print(
                    "\nRestoring original "
                    "verification method..."
                )

                tx_hash = (
                    registry.functions
                    .updateVerificationMethod(
                        ukprn,
                        original_method,
                    )
                    .transact(
                        {
                            "from":
                            web3.eth.accounts[
                                0
                            ]
                        }
                    )
                )

                transaction_wait(
                    web3,
                    tx_hash,
                )

            if not active:

                print(
                    "\nReactivating issuer..."
                )

                tx_hash = (
                    registry.functions
                    .reactivateIssuer(
                        ukprn
                    )
                    .transact(
                        {
                            "from":
                            web3.eth.accounts[
                                0
                            ]
                        }
                    )
                )

                transaction_wait(
                    web3,
                    tx_hash,
                )

            restored = (
                registry.functions
                .getIssuer(
                    ukprn
                )
                .call()
            )

            print(
                "\nREGISTRY RESTORATION"
            )

            print(
                "Active:",
                restored[3],
            )

            print(
                "Verification method restored:",
                (
                    restored[2]
                    == original_method
                ),
            )

        except Exception as error:

            print(
                "\nWARNING: "
                "Registry restoration failed:",
                error,
            )

    print_results(
        results
    )


if __name__ == "__main__":
    main()