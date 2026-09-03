"""
Controlled Trust-Layer Attack Experiments
=========================================

Evaluates the combined academic credential verification framework
against controlled trust and integrity attack scenarios.

The experiments distinguish between:

1. credential integrity failure
2. blockchain authorization failure
3. successful trusted verification

In this first experiment set, most attacks modify signed credential
content. Therefore, cryptographic verification fails before the
blockchain authorization stage is reached.
"""

from __future__ import annotations

import copy
from typing import Any

from trust_verifier import (
    DEFAULT_CREDENTIAL,
    blockchain_status_text,
    verify_trust,
)
from verifier import load_json


def run_scenario(
    name: str,
    credential: dict[str, Any],
    expected_trusted: bool,
) -> dict[str, Any]:
    """
    Run one controlled trust scenario.
    """

    result = verify_trust(
        credential
    )

    passed = (
        result["trusted"]
        == expected_trusted
    )

    return {
        "scenario": name,

        "crypto": (
            "PASS"
            if result[
                "cryptographic_valid"
            ]
            else "FAIL"
        ),

        "blockchain": (
            blockchain_status_text(
                result[
                    "blockchain_authorized"
                ]
            )
        ),

        "decision": (
            "TRUSTED"
            if result["trusted"]
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


def print_results(
    results: list[dict[str, Any]],
) -> None:
    """
    Print experiment results as a compact table.
    """

    print(
        "\nCONTROLLED TRUST-LAYER EXPERIMENTS\n"
    )

    print(
        f"{'Scenario':<30}"
        f"{'Crypto':<10}"
        f"{'Blockchain':<18}"
        f"{'Decision':<12}"
        f"{'Expected':<12}"
        f"{'Test':<8}"
    )

    print(
        "-" * 90
    )

    for result in results:
        print(
            f"{result['scenario']:<30}"
            f"{result['crypto']:<10}"
            f"{result['blockchain']:<18}"
            f"{result['decision']:<12}"
            f"{result['expected']:<12}"
            f"{result['test']:<8}"
        )

    passed = sum(
        1
        for result in results
        if result["test"] == "PASS"
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
            result["reason"],
        )


def main() -> None:
    """
    Execute controlled integrity and trust scenarios.
    """

    original = load_json(
        DEFAULT_CREDENTIAL
    )

    results: list[
        dict[str, Any]
    ] = []

    # --------------------------------------------------
    # Scenario 1
    #
    # Valid signed credential issued by an
    # authorised blockchain-registered issuer.
    #
    # Expected:
    # Crypto       -> PASS
    # Blockchain  -> AUTHORIZED
    # Decision    -> TRUSTED
    # --------------------------------------------------

    results.append(
        run_scenario(
            name="valid-authorised",
            credential=copy.deepcopy(
                original
            ),
            expected_trusted=True,
        )
    )

    # --------------------------------------------------
    # Scenario 2
    #
    # Programme claim is modified after signing.
    #
    # Expected:
    # Crypto       -> FAIL
    # Blockchain  -> NOT CHECKED
    # Decision    -> REJECTED
    # --------------------------------------------------

    tampered_programme = (
        copy.deepcopy(
            original
        )
    )

    tampered_programme[
        "credentialSubject"
    ][
        "programme"
    ] = (
        "BSc Artificial Intelligence"
    )

    results.append(
        run_scenario(
            name="tampered-programme",
            credential=(
                tampered_programme
            ),
            expected_trusted=False,
        )
    )

    # --------------------------------------------------
    # Scenario 3
    #
    # Institutional issuer DID is modified after
    # the credential has been signed.
    #
    # Because issuer is part of the signed
    # credential, signature verification must fail.
    #
    # Expected:
    # Crypto       -> FAIL
    # Blockchain  -> NOT CHECKED
    # Decision    -> REJECTED
    # --------------------------------------------------

    tampered_issuer = (
        copy.deepcopy(
            original
        )
    )

    tampered_issuer[
        "issuer"
    ] = (
        "did:example:issuer:"
        "ukprn-99999999"
    )

    results.append(
        run_scenario(
            name="tampered-issuer",
            credential=tampered_issuer,
            expected_trusted=False,
        )
    )

    # --------------------------------------------------
    # Scenario 4
    #
    # verificationMethod inside the Data Integrity
    # proof is modified.
    #
    # The proof configuration is itself protected by
    # the Data Integrity signature construction.
    #
    # Expected:
    # Crypto       -> FAIL
    # Blockchain  -> NOT CHECKED
    # Decision    -> REJECTED
    # --------------------------------------------------

    tampered_key = (
        copy.deepcopy(
            original
        )
    )

    tampered_key[
        "proof"
    ][
        "verificationMethod"
    ] = (
        "did:key:z6MkiiFake"
        "#z6MkiiFake"
    )

    results.append(
        run_scenario(
            name="tampered-signing-key",
            credential=tampered_key,
            expected_trusted=False,
        )
    )

    # --------------------------------------------------
    # Scenario 5
    #
    # UKPRN claim is modified after signing.
    #
    # issuerUkprn is inside credentialSubject and is
    # therefore protected by the credential signature.
    #
    # Expected:
    # Crypto       -> FAIL
    # Blockchain  -> NOT CHECKED
    # Decision    -> REJECTED
    # --------------------------------------------------

    tampered_ukprn = (
        copy.deepcopy(
            original
        )
    )

    tampered_ukprn[
        "credentialSubject"
    ][
        "issuerUkprn"
    ] = "99999999"

    results.append(
        run_scenario(
            name="tampered-ukprn",
            credential=tampered_ukprn,
            expected_trusted=False,
        )
    )

    print_results(
        results
    )


if __name__ == "__main__":
    main()