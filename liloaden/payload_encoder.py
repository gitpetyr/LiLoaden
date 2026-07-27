#!/usr/bin/env python3
"""Stream LZMA -> AES-GCM -> LZMA and emit the result as IPv6 literals."""

from __future__ import annotations

import argparse
import ipaddress
import lzma
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise SystemExit("Missing dependency 'cryptography'. Run: python -m pip install -r requirements.txt") from exc

MAGIC = b"LIL2"
AAD = b"LiLoaden:LZMA:AES-GCM:LZMA:IPv6:v2"
CHUNK_SIZE = 1024 * 1024


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stream data through LZMA, AES-GCM, and LZMA, then emit an IPv6 C++ header.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Example: %(prog)s input.bin payload.h --key-file aes.key",
    )
    parser.add_argument("input", type=Path, metavar="INPUT", help="binary input file")
    parser.add_argument("output", type=Path, metavar="OUTPUT_HEADER", help="generated C++ header path")
    key = parser.add_mutually_exclusive_group(required=True)
    key.add_argument("--key-hex", metavar="HEX", help="AES key as exactly 32, 48, or 64 hexadecimal characters")
    key.add_argument("--key-file", type=Path, metavar="FILE", help="file containing exactly 16, 24, or 32 raw AES key bytes")
    parser.add_argument("--namespace", default="liloaden_payload", metavar="CXX_NAMESPACE", help="C++ namespace for generated constants; nested names such as foo::bar are accepted")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE, metavar="BYTES", help="streaming I/O chunk size; must be at least 4096 bytes")
    parser.add_argument("--temp-dir", type=Path, metavar="DIR", help="intermediate-file directory (system temporary directory if omitted)")
    return parser.parse_args()


def load_key(args: argparse.Namespace) -> bytes:
    try:
        key = bytes.fromhex(args.key_hex) if args.key_hex is not None else args.key_file.read_bytes()
    except ValueError as exc:
        raise ValueError("--key-hex must be a valid hexadecimal string") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError("the AES key must contain exactly 16, 24, or 32 bytes")
    return key


def validate(args: argparse.Namespace) -> None:
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not all(identifier.fullmatch(part) for part in args.namespace.split("::")):
        raise ValueError("--namespace must be a valid C++ namespace, for example foo or foo::bar")
    if args.chunk_size < 4096:
        raise ValueError("--chunk-size must be at least 4096")
    if not args.input.is_file():
        raise ValueError(f"input does not exist or is not a regular file: {args.input}")


def copy_chunks(source: BinaryIO, target: BinaryIO, chunk_size: int) -> None:
    while chunk := source.read(chunk_size):
        target.write(chunk)


def compress(source: Path, target: Path, chunk_size: int) -> None:
    with source.open("rb") as src, lzma.open(target, "wb", format=lzma.FORMAT_XZ) as dst:
        copy_chunks(src, dst, chunk_size)


def encrypt(source: Path, target: Path, key: bytes, chunk_size: int) -> None:
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(AAD)
    with source.open("rb") as src, target.open("wb") as dst:
        dst.write(MAGIC + bytes((len(key),)) + nonce)
        while chunk := src.read(chunk_size):
            dst.write(encryptor.update(chunk))
        dst.write(encryptor.finalize())
        dst.write(encryptor.tag)


def write_header(
    source: Path,
    output: Path,
    namespace: str,
    payload: Path,
    original_size: int,
    inner_size: int,
    key_bits: int,
) -> int:
    payload_size = payload.stat().st_size
    count = (payload_size + 15) // 16
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=output.parent,
            prefix=f".{output.name}.", suffix=".tmp", delete=False
        ) as header:
            temporary = Path(header.name)
            header.write(
                f"// Generated from {source.name}. Do not edit.\n#pragma once\n\n"
                "#include <array>\n#include <cstddef>\n#include <string_view>\n\n"
                f"namespace {namespace} {{\n\n"
                f'inline constexpr std::string_view kCipher = "AES-{key_bits}-GCM";\n'
                'inline constexpr std::string_view kPipeline = "LZMA/XZ -> AES-GCM -> LZMA/XZ";\n'
                f"inline constexpr std::size_t kOriginalSize = {original_size};\n"
                f"inline constexpr std::size_t kInnerCompressedSize = {inner_size};\n"
                f"inline constexpr std::size_t kCompressedSize = {payload_size};\n"
                f"inline constexpr std::array<const char*, {count}> kIpv6Payload{{{{\n"
            )
            with payload.open("rb") as data:
                for _ in range(count):
                    block = data.read(16)
                    block += b"\0" * (16 - len(block))
                    header.write(f'    "{ipaddress.IPv6Address(block).exploded}",\n')
            header.write(f"}}}};\n\n}}  // namespace {namespace}\n")
            header.flush()
            os.fsync(header.fileno())
        os.replace(temporary, output)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return count


def encode_file(
    source: Path,
    output: Path,
    key: bytes,
    namespace: str = "liloaden_payload",
    chunk_size: int = CHUNK_SIZE,
    temp_dir: Path | None = None,
) -> tuple[int, int, int, int]:
    if len(key) not in (16, 24, 32):
        raise ValueError("the AES key must contain exactly 16, 24, or 32 bytes")
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not all(identifier.fullmatch(part) for part in namespace.split("::")):
        raise ValueError("namespace must be a valid C++ namespace")
    if chunk_size < 4096:
        raise ValueError("chunk_size must be at least 4096")
    if not source.is_file():
        raise ValueError(f"input does not exist or is not a regular file: {source}")

    original_size = source.stat().st_size
    if temp_dir:
        temp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="liloaden-", dir=str(temp_dir) if temp_dir else None
    ) as directory:
        work = Path(directory)
        inner, encrypted, outer = work / "inner.xz", work / "encrypted.bin", work / "outer.xz"
        compress(source, inner, chunk_size)
        inner_size = inner.stat().st_size
        encrypt(inner, encrypted, key, chunk_size)
        compress(encrypted, outer, chunk_size)
        outer_size = outer.stat().st_size
        count = write_header(
            source, output, namespace, outer,
            original_size, inner_size, len(key) * 8
        )
    return original_size, inner_size, outer_size, count


def main() -> int:
    args = arguments()
    try:
        validate(args)
        key = load_key(args)
        original_size, inner_size, outer_size, count = encode_file(
            args.input, args.output, key, args.namespace, args.chunk_size, args.temp_dir
        )
    except (OSError, ValueError, lzma.LZMAError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"Generated {args.output}: {original_size} -> {inner_size} -> "
        f"{outer_size} bytes, {count} IPv6 addresses"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
