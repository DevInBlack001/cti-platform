"""Generates and loads this node's Ed25519 signing key pair.

A node's Ed25519 key pair is its permanent identity: every Threat Observation
produced is signed with the same key for as long as that key exists. This module
handles creating the key pair on first use and loading it on every run afterward.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collection.config import ensure_private_directory, resolve_key_dir

# Filenames for the node's Ed25519 key pair, stored in PEM format.
PRIVATE_KEY_FILENAME = "node_private_key.pem"
PUBLIC_KEY_FILENAME = "node_public_key.pem"


def load_or_create_node_key(key_dir: Path | None = None) -> Ed25519PrivateKey:
    """Loads this node's private key if one exists, otherwise generates a fresh one.

    On first use, generates an Ed25519 key pair and stores both the private
    (0o600) and public (0o644) keys in PEM format. On subsequent calls, loads
    the existing private key. The key directory itself is created with 0o700
    permissions and defaults to ~/.local/share/cti-platform/keys/.
    """
    directory = key_dir if key_dir is not None else resolve_key_dir().value
    ensure_private_directory(directory)
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
    """Returns a short, stable identifier for this node.

    Derives a 16-character hex fingerprint from the SHA256 hash of the node's
    public key. The fingerprint is stable across runs and serves as the
    reporting_node_id in Threat Observations.
    """
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_bytes).hexdigest()[:16]
