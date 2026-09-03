"""
Credential Status Blockchain Verifier
=====================================

Connects to the local Hardhat blockchain and reads
credential-level registration and revocation status
from CredentialStatusRegistry.

Research prototype only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from web3 import Web3


# ============================================================
# Project configuration
# ============================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

RPC_URL = (
    "http://127.0.0.1:8545"
)

STATUS_REGISTRY_ADDRESS = (
    "0x0165878A594ca255338adfa4d48449f69242Eb8F"
)

STATUS_ARTIFACT_PATH = (
    PROJECT_ROOT
    / "blockchain"
    / "artifacts"
    / "contracts"
    / "CredentialStatusRegistry.sol"
    / "CredentialStatusRegistry.json"
)


# ============================================================
# ABI loading
# ============================================================

def load_status_registry_abi() -> list[dict[str, Any]]:
    """
    Load the CredentialStatusRegistry ABI from the
    Hardhat compilation artifact.
    """

    if not STATUS_ARTIFACT_PATH.exists():
        raise FileNotFoundError(
            "CredentialStatusRegistry artifact not found: "
            f"{STATUS_ARTIFACT_PATH}"
        )

    with STATUS_ARTIFACT_PATH.open(
        "r",
        encoding="utf-8",
    ) as file_obj:

        artifact = json.load(
            file_obj
        )

    abi = artifact.get(
        "abi"
    )

    if not abi:
        raise ValueError(
            "ABI missing from "
            "CredentialStatusRegistry artifact."
        )

    return abi


# ============================================================
# Blockchain connection
# ============================================================

def connect_to_status_blockchain() -> Web3:
    """
    Connect to the local Hardhat blockchain.
    """

    web3 = Web3(
        Web3.HTTPProvider(
            RPC_URL
        )
    )

    if not web3.is_connected():
        raise ConnectionError(
            "Unable to connect to local blockchain "
            f"at {RPC_URL}"
        )

    return web3


def get_status_registry_contract(
    web3: Web3,
):
    """
    Return a Web3 contract instance for the
    CredentialStatusRegistry.
    """

    abi = (
        load_status_registry_abi()
    )

    address = (
        Web3.to_checksum_address(
            STATUS_REGISTRY_ADDRESS
        )
    )

    contract_code = (
        web3.eth.get_code(
            address
        )
    )

    if (
        contract_code
        in (
            b"",
            b"\x00",
        )
    ):
        raise RuntimeError(
            "No contract code exists at "
            f"{address}. "
            "The local Hardhat node may have been "
            "restarted."
        )

    return web3.eth.contract(
        address=address,
        abi=abi,
    )


# ============================================================
# Credential identifier hashing
# ============================================================

def credential_id_to_hash(
    credential_id: str,
) -> bytes:
    """
    Convert the public credential identifier into
    the bytes32 value stored by the Solidity contract.

    Solidity tests use:

        keccak256(toUtf8Bytes(credentialId))

    Therefore Python must use Ethereum Keccak-256,
    not standard hashlib.sha3_256.
    """

    if (
        not isinstance(
            credential_id,
            str,
        )
        or not credential_id.strip()
    ):
        raise ValueError(
            "Credential ID must be a "
            "non-empty string."
        )

    return Web3.keccak(
        text=credential_id
    )


# ============================================================
# Registry queries
# ============================================================

def is_credential_registered(
    credential_id: str,
) -> bool:
    """
    Return True if the credential identifier has
    been registered on-chain.
    """

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

    return bool(
        registry.functions
        .isCredentialRegistered(
            credential_hash
        )
        .call()
    )


def is_credential_revoked(
    credential_id: str,
) -> bool:
    """
    Return True if the credential is revoked.
    """

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

    return bool(
        registry.functions
        .isCredentialRevoked(
            credential_hash
        )
        .call()
    )


def is_credential_valid(
    credential_id: str,
) -> bool:
    """
    Return True only when the credential is
    registered and not revoked.
    """

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

    return bool(
        registry.functions
        .isCredentialValid(
            credential_hash
        )
        .call()
    )


def get_credential_status(
    credential_id: str,
) -> dict[str, Any]:
    """
    Read full credential status metadata.

    Raises if the credential is not registered.
    """

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

    result = (
        registry.functions
        .getCredentialStatus(
            credential_hash
        )
        .call()
    )

    return {
        "credential_id": credential_id,
        "credential_hash": (
            "0x"
            + credential_hash.hex()
        ),
        "registered": bool(
            result[0]
        ),
        "revoked": bool(
            result[1]
        ),
        "registered_at": int(
            result[2]
        ),
        "revoked_at": int(
            result[3]
        ),
    }


# ============================================================
# Command-line test
# ============================================================

def main() -> None:
    """
    Display blockchain connection information.

    At this stage the sample credential has not yet
    been registered, so the expected validity result
    is False.
    """

    credential_id = (
        "urn:academic-credential:"
        "cred-000000000001"
    )

    web3 = (
        connect_to_status_blockchain()
    )

    print(
        "Connecting to:",
        RPC_URL,
    )

    print(
        "Blockchain connected:",
        web3.is_connected(),
    )

    print(
        "Chain ID:",
        web3.eth.chain_id,
    )

    print(
        "Latest block:",
        web3.eth.block_number,
    )

    print(
        "CredentialStatusRegistry:",
        STATUS_REGISTRY_ADDRESS,
    )

    credential_hash = (
        credential_id_to_hash(
            credential_id
        )
    )

    print(
        "\nCREDENTIAL STATUS IDENTITY"
    )

    print(
        "Credential ID:",
        credential_id,
    )

    print(
        "Credential hash:",
        "0x" + credential_hash.hex(),
    )

    print(
        "\nRegistered:",
        is_credential_registered(
            credential_id
        ),
    )

    print(
        "Revoked:",
        is_credential_revoked(
            credential_id
        ),
    )

    print(
        "Valid:",
        is_credential_valid(
            credential_id
        ),
    )


if __name__ == "__main__":
    main()