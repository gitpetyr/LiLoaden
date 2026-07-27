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
    raise SystemExit("缺少 cryptography，请运行: python -m pip install -r requirements.txt") from exc

MAGIC = b"LIL2"
AAD = b"LiLoaden:LZMA:AES-GCM:LZMA:IPv6:v2"
CHUNK_SIZE = 1024 * 1024


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="流式执行 LZMA -> AES-GCM -> LZMA，并生成 IPv6 C++ 头文件。"
    )
    parser.add_argument("input", type=Path, help="输入二进制文件")
    parser.add_argument("output", type=Path, help="输出 .h 文件")
    key = parser.add_mutually_exclusive_group(required=True)
    key.add_argument("--key-hex", help="32/48/64 个十六进制字符的 AES 密钥")
    key.add_argument("--key-file", type=Path, help="16/24/32 字节原始 AES 密钥文件")
    parser.add_argument("--namespace", default="liloaden_payload")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    parser.add_argument("--temp-dir", type=Path, help="中间文件目录，需有足够可用空间")
    return parser.parse_args()


def load_key(args: argparse.Namespace) -> bytes:
    try:
        key = bytes.fromhex(args.key_hex) if args.key_hex is not None else args.key_file.read_bytes()
    except ValueError as exc:
        raise ValueError("--key-hex 不是有效的十六进制字符串") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥必须为 16、24 或 32 字节")
    return key


def validate(args: argparse.Namespace) -> None:
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not all(identifier.fullmatch(part) for part in args.namespace.split("::")):
        raise ValueError("--namespace 不是合法的 C++ 命名空间")
    if args.chunk_size < 4096:
        raise ValueError("--chunk-size 不能小于 4096")
    if not args.input.is_file():
        raise ValueError(f"输入文件不存在或不是普通文件: {args.input}")


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
        raise ValueError("AES 密钥必须为 16、24 或 32 字节")
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not all(identifier.fullmatch(part) for part in namespace.split("::")):
        raise ValueError("namespace 不是合法的 C++ 命名空间")
    if chunk_size < 4096:
        raise ValueError("chunk_size 不能小于 4096")
    if not source.is_file():
        raise ValueError(f"输入文件不存在或不是普通文件: {source}")

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
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    print(
        f"已生成 {args.output}: {original_size} -> {inner_size} -> "
        f"{outer_size} 字节，{count} 个 IPv6 地址"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
