"""Encoder module contract, registry, and stable dispatch entry points."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from . import lzma_aes_ipv6


@dataclass(frozen=True)
class CppDecoder:
    """Files and build settings required by an encoder's C++ decoder."""

    header: str
    source: str
    cmake_packages: tuple[str, ...] = ()
    cmake_libraries: tuple[str, ...] = ()


@dataclass(frozen=True)
class EncoderArtifacts:
    """Additional generated files owned by an encoder implementation."""

    headers: Mapping[str, str]


class EncoderModule(Protocol):
    NAME: str
    CLI_EPILOG: str

    def add_cli_arguments(self, parser: argparse.ArgumentParser) -> None: ...

    def encode_from_cli(
        self,
        args: argparse.Namespace,
        source: Path,
        output: Path,
        namespace: str,
    ) -> EncoderArtifacts: ...

    def encode(self, source: Path, output: Path, **options: Any) -> Any: ...

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
    **options: Any,
) -> Any:
    """Dispatch encoder-specific keyword options to the selected module."""
    implementation = get_encoder(encoder)
    return implementation.encode(source=source, output=output, **options)


__all__ = [
    "CppDecoder",
    "EncoderArtifacts",
    "EncoderModule",
    "available_encoders",
    "encode",
    "get_encoder",
]
