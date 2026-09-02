"""Security checks for trusted serialized ML artifacts."""
from __future__ import annotations

import hashlib
from pathlib import Path


class ModelIntegrityError(RuntimeError):
    """Raised when a model artifact fails an integrity policy."""


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_model_artifact(
    path: str | Path,
    expected_sha256: str | None = None,
    *,
    require_hash: bool = False,
) -> str:
    """Verify a model artifact before joblib/pickle deserialization."""
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise ModelIntegrityError(f"model artifact must be a regular file: {p}")
    actual = sha256_file(p)
    expected = (expected_sha256 or "").strip().lower()
    if require_hash and not expected:
        raise ModelIntegrityError(f"no SHA-256 allow-list entry configured for model: {p}")
    if expected and actual != expected:
        raise ModelIntegrityError(
            f"model SHA-256 mismatch for {p}: expected {expected}, got {actual}"
        )
    return actual
