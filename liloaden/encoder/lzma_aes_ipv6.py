"""LZMA -> AES-GCM -> LZMA encoder with IPv6-literal output."""

from __future__ import annotations

from pathlib import Path

from ..payload_encoder import CHUNK_SIZE, encode_file


def encode(
    source: Path,
    output: Path,
    key: bytes,
    namespace: str = "liloaden_payload",
    chunk_size: int = CHUNK_SIZE,
    temp_dir: Path | None = None,
) -> tuple[int, int, int, int]:
    return encode_file(source, output, key, namespace, chunk_size, temp_dir)


__all__ = ["CHUNK_SIZE", "encode"]
