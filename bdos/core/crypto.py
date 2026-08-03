"""Cryptographic primitives for the Safety Notice layer.

BDOS validates privileged actions with unforgeable proof of *legitimacy*, not
proof of *work*. Ed25519 signatures are the mechanism: fast to verify, small,
and impossible to forge without the private key. This module is deliberately
thin -- a single, auditable place where key handling lives.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_RAW = serialization.Encoding.Raw
_PUB = serialization.PublicFormat.Raw
_PRIV = serialization.PrivateFormat.Raw
_NOENC = serialization.NoEncryption()


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def sign(sk: Ed25519PrivateKey, data: bytes) -> bytes:
    return sk.sign(data)


def verify(pk: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        pk.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def public_bytes(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(_RAW, _PUB)


def private_bytes(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(_RAW, _PRIV, _NOENC)


def load_public(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def load_private(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def key_id(pk: Ed25519PublicKey) -> str:
    """Short, stable identifier for a public key (first 16 hex of SHA-256)."""
    return hashlib.sha256(public_bytes(pk)).hexdigest()[:16]


def b64e(data: bytes) -> str:
    """URL-safe base64 without padding (compact, header/URL friendly)."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
