"""Generates and loads this node's Ed25519 signing key pair."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collection.config import resolve_key_dir

PRIVATE_KEY_FILENAME = "node_private_key.pem"
PUBLIC_KEY_FILENAME = "node_public_key.pem"


def load_or_create_node_key(key_dir: Path | None = None) -> Ed25519PrivateKey:
    """Returns this node's private key, generating one on first use."""
    directory = key_dir if key_dir is not None else resolve_key_dir().value
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_key_path = directory / PRIVATE_KEY_FILENAME

    if private_key_path.exists():
        fd = os.open(str(private_key_path), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with os.fdopen(fd, "rb") as f:
                stored_bytes = f.read()
        except OSError:
            os.close(fd)
            raise
        return serialization.load_pem_private_key(stored_bytes, password=None)

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(
        str(private_key_path),
        os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_NOFOLLOW,
        mode=0o600,
    )
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)

    public_key_path = directory / PUBLIC_KEY_FILENAME
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fd = os.open(
        str(public_key_path),
        os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_NOFOLLOW,
        mode=0o644,
    )
    with os.fdopen(fd, "wb") as f:
        f.write(public_bytes)

    return private_key


def node_fingerprint(private_key: Ed25519PrivateKey) -> str:
    """A short, stable identifier for this node, derived from its public key."""
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_bytes).hexdigest()[:16]
