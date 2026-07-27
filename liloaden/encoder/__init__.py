"""Encoder registry and stable dispatch entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from . import lzma_aes_ipv6


class Encoder(Protocol):
    def encode(
        self, source: Path, output: Path, key: bytes, namespace: str,
        chunk_size: int, temp_dir: Path | None,
    ) -> tuple[int, int, int, int]: ...


_ENCODERS: dict[str, Encoder] = {"lzma-aes-ipv6": lzma_aes_ipv6}


def available_encoders() -> tuple[str, ...]:
    return tuple(sorted(_ENCODERS))


def encode(
    encoder: str,
    source: Path,
    output: Path,
    key: bytes,
    namespace: str = "liloaden_payload",
    chunk_size: int = lzma_aes_ipv6.CHUNK_SIZE,
    temp_dir: Path | None = None,
) -> tuple[int, int, int, int]:
    """Encode a file through the selected encoder's common entry point."""
    try:
        implementation = _ENCODERS[encoder]
    except KeyError as exc:
        choices = ", ".join(available_encoders())
        raise ValueError(f"未知编码器 {encoder!r}；可用编码器: {choices}") from exc
    return implementation.encode(source, output, key, namespace, chunk_size, temp_dir)


__all__ = ["available_encoders", "encode"]
