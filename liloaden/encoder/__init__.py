"""Encoder module contract, registry, and stable dispatch entry points."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import lzma_aes_ipv6


@dataclass(frozen=True)
class CppDecoder:
    """Files and build settings required by an encoder's C++ decoder."""

    header: str
    source: str
    cmake_packages: tuple[str, ...] = ()
    cmake_libraries: tuple[str, ...] = ()


class EncoderModule(Protocol):
    NAME: str
    CHUNK_SIZE: int

    def encode(
        self, source: Path, output: Path, key: bytes, namespace: str,
        chunk_size: int, temp_dir: Path | None,
    ) -> tuple[int, int, int, int]: ...

    def cpp_decoder(self, namespace: str) -> CppDecoder: ...


_ENCODERS: dict[str, EncoderModule] = {lzma_aes_ipv6.NAME: lzma_aes_ipv6}


def available_encoders() -> tuple[str, ...]:
    return tuple(sorted(_ENCODERS))


def get_encoder(name: str) -> EncoderModule:
    """Return a module implementing the complete Python/C++ encoder contract."""
    try:
        return _ENCODERS[name]
    except KeyError as exc:
        choices = ", ".join(available_encoders())
        raise ValueError(f"unknown encoder {name!r}; available encoders: {choices}") from exc


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
    implementation = get_encoder(encoder)
    return implementation.encode(source, output, key, namespace, chunk_size, temp_dir)


__all__ = ["CppDecoder", "EncoderModule", "available_encoders", "encode", "get_encoder"]
