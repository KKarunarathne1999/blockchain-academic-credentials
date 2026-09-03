"""
Cryptographic Utilities for Academic Credentials
=================================================

Implements the cryptographic primitives required by the research
prototype's W3C Data Integrity EdDSA signing workflow.

The implementation uses:

- Ed25519
- RFC 8785 JSON Canonicalization Scheme (JCS)
- SHA-256
- Multibase base58-btc
- Multikey representation for Ed25519 public keys

The intended cryptosuite is:

    eddsa-jcs-2022

This module is for research and experimental use.

Private keys are written only to the local keys/ directory, which
must remain excluded from version control.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import rfc8785

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

KEY_DIR = PROJECT_ROOT / "keys"


# ============================================================
# Constants
# ============================================================

BASE58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
)

BASE58_INDEX = {
    character: index
    for index, character
    in enumerate(BASE58_ALPHABET)
}

MULTIBASE_BASE58BTC_PREFIX = "z"

# Multicodec prefix for Ed25519 public keys:
# ed25519-pub = 0xed
# unsigned-varint representation = 0xed 0x01
ED25519_MULTICODEC_PREFIX = bytes(
    [0xED, 0x01]
)


# ============================================================
# Base58-btc
# ============================================================

def base58btc_encode(data: bytes) -> str:
    """
    Encode bytes using Bitcoin base58.

    The returned value does not contain the Multibase 'z' prefix.
    """

    if not data:
        return ""

    number = int.from_bytes(
        data,
        byteorder="big",
    )

    encoded = ""

    while number > 0:

        number, remainder = divmod(
            number,
            58,
        )

        encoded = (
            BASE58_ALPHABET[remainder]
            + encoded
        )

    leading_zero_count = 0

    for byte in data:

        if byte == 0:
            leading_zero_count += 1

        else:
            break

    return (
        "1" * leading_zero_count
        + encoded
    )


def base58btc_decode(value: str) -> bytes:
    """Decode Bitcoin base58 text into bytes."""

    if not value:
        return b""

    number = 0

    for character in value:

        if character not in BASE58_INDEX:

            raise ValueError(
                f"Invalid base58 character: "
                f"{character!r}"
            )

        number = (
            number * 58
            + BASE58_INDEX[character]
        )

    if number == 0:

        decoded = b""

    else:

        decoded = number.to_bytes(
            (number.bit_length() + 7) // 8,
            byteorder="big",
        )

    leading_ones = 0

    for character in value:

        if character == "1":
            leading_ones += 1

        else:
            break

    return (
        b"\x00" * leading_ones
        + decoded
    )


def multibase_base58btc_encode(
    data: bytes,
) -> str:
    """Encode bytes as Multibase base58-btc."""

    return (
        MULTIBASE_BASE58BTC_PREFIX
        + base58btc_encode(data)
    )


def multibase_base58btc_decode(
    value: str,
) -> bytes:
    """Decode Multibase base58-btc data."""

    if not value.startswith(
        MULTIBASE_BASE58BTC_PREFIX
    ):

        raise ValueError(
            "Expected Multibase base58-btc "
            "value beginning with 'z'."
        )

    return base58btc_decode(
        value[1:]
    )


# ============================================================
# Key generation
# ============================================================

def generate_ed25519_key_pair(
    issuer_name: str,
) -> tuple[Path, Path]:
    """
    Generate an Ed25519 key pair.

    Returns
    -------
    tuple[Path, Path]
        private key path and public key path.
    """

    KEY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    private_key = (
        Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    private_key_path = (
        KEY_DIR
        / f"{issuer_name}_private.pem"
    )

    public_key_path = (
        KEY_DIR
        / f"{issuer_name}_public.pem"
    )

    private_bytes = (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=(
                serialization.PrivateFormat.PKCS8
            ),
            encryption_algorithm=(
                serialization.NoEncryption()
            ),
        )
    )

    public_bytes = (
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=(
                serialization.PublicFormat
                .SubjectPublicKeyInfo
            ),
        )
    )

    private_key_path.write_bytes(
        private_bytes
    )

    public_key_path.write_bytes(
        public_bytes
    )

    return (
        private_key_path,
        public_key_path,
    )


# ============================================================
# Key loading
# ============================================================

def load_private_key(
    path: Path,
) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM."""

    key = serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )

    if not isinstance(
        key,
        Ed25519PrivateKey,
    ):

        raise TypeError(
            "Private key is not Ed25519."
        )

    return key


def load_public_key(
    path: Path,
) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM."""

    key = serialization.load_pem_public_key(
        path.read_bytes()
    )

    if not isinstance(
        key,
        Ed25519PublicKey,
    ):

        raise TypeError(
            "Public key is not Ed25519."
        )

    return key


# ============================================================
# Public-key representations
# ============================================================

def raw_public_key_bytes(
    public_key: Ed25519PublicKey,
) -> bytes:
    """Return the raw 32-byte Ed25519 public key."""

    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_multibase(
    public_key: Ed25519PublicKey,
) -> str:
    """
    Encode an Ed25519 public key as a Multikey
    publicKeyMultibase value.
    """

    raw_key = raw_public_key_bytes(
        public_key
    )

    multikey_bytes = (
        ED25519_MULTICODEC_PREFIX
        + raw_key
    )

    return multibase_base58btc_encode(
        multikey_bytes
    )


def public_key_from_multibase(
    value: str,
) -> Ed25519PublicKey:
    """
    Restore an Ed25519 public key from its
    publicKeyMultibase representation.
    """

    decoded = multibase_base58btc_decode(
        value
    )

    if not decoded.startswith(
        ED25519_MULTICODEC_PREFIX
    ):

        raise ValueError(
            "Multikey is not an Ed25519 "
            "public key."
        )

    raw_key = decoded[
        len(ED25519_MULTICODEC_PREFIX):
    ]

    if len(raw_key) != 32:

        raise ValueError(
            "Invalid Ed25519 public key length."
        )

    return Ed25519PublicKey.from_public_bytes(
        raw_key
    )


# ============================================================
# did:key
# ============================================================

def create_did_key(
    public_key: Ed25519PublicKey,
) -> str:
    """
    Construct a did:key identifier from an
    Ed25519 public key.
    """

    multikey = public_key_multibase(
        public_key
    )

    return (
        f"did:key:{multikey}"
    )


def create_verification_method(
    public_key: Ed25519PublicKey,
) -> str:
    """
    Construct the verificationMethod identifier
    for a did:key Ed25519 key.
    """

    multikey = public_key_multibase(
        public_key
    )

    return (
        f"did:key:{multikey}"
        f"#{multikey}"
    )


# ============================================================
# JCS canonicalization
# ============================================================

def canonicalize_json(
    value: Any,
) -> bytes:
    """
    Canonicalize JSON according to RFC 8785.

    rfc8785.dumps returns canonical UTF-8 bytes.
    """

    return rfc8785.dumps(
        value
    )


# ============================================================
# Hashing
# ============================================================

def sha256_bytes(
    data: bytes,
) -> bytes:
    """Return raw SHA-256 digest bytes."""

    return hashlib.sha256(
        data
    ).digest()


def create_hash_data(
    unsecured_document: dict[str, Any],
    proof_configuration: dict[str, Any],
) -> bytes:
    """
    Construct hashData for eddsa-jcs-2022.

    According to the cryptosuite:

        SHA256(canonical proof config)
            ||
        SHA256(canonical unsecured document)
    """

    canonical_document = canonicalize_json(
        unsecured_document
    )

    canonical_proof_config = canonicalize_json(
        proof_configuration
    )

    proof_config_hash = sha256_bytes(
        canonical_proof_config
    )

    document_hash = sha256_bytes(
        canonical_document
    )

    return (
        proof_config_hash
        + document_hash
    )


# ============================================================
# Signing and verification
# ============================================================

def sign_hash_data(
    private_key: Ed25519PrivateKey,
    hash_data: bytes,
) -> bytes:
    """Sign hashData using Ed25519."""

    return private_key.sign(
        hash_data
    )


def verify_hash_data(
    public_key: Ed25519PublicKey,
    signature: bytes,
    hash_data: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.

    Returns True when valid and False otherwise.
    """

    try:

        public_key.verify(
            signature,
            hash_data,
        )

        return True

    except Exception:

        return False