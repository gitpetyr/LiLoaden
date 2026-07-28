"""ChaCha20 stream encoder with Base85 C++ header output."""

from __future__ import annotations

import argparse
import base64
import os
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

if TYPE_CHECKING:
    from . import CppDecoder, EncoderArtifacts

NAME = "chacha20-base85"
CLI_EPILOG = (
    "Example: %(prog)s input.bin generated-project --encoder chacha20-base85 "
    "--key-hex "
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)
MAGIC = b"LIL4"
CHUNK_SIZE = 1024 * 1024
BASE85_CHARS_PER_LITERAL = 16380


def add_cli_arguments(parser: argparse.ArgumentParser) -> None:
    """Register arguments specific to the ChaCha20/Base85 pipeline."""
    group = parser.add_argument_group(f"{NAME} options")
    keys = group.add_mutually_exclusive_group(required=True)
    keys.add_argument(
        "--key-hex",
        metavar="HEX",
        help="ChaCha20 key as exactly 64 hexadecimal characters",
    )
    keys.add_argument(
        "--key-file",
        type=Path,
        metavar="FILE",
        help="file containing exactly 32 raw ChaCha20 key bytes",
    )
    group.add_argument(
        "--chunk-size",
        type=int,
        default=CHUNK_SIZE,
        metavar="BYTES",
        help="streaming I/O chunk size; must be at least 4096 bytes",
    )


def _validate(source: Path, namespace: str, chunk_size: int) -> None:
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not all(identifier.fullmatch(part) for part in namespace.split("::")):
        raise ValueError("namespace must be a valid C++ namespace")
    if chunk_size < 4096:
        raise ValueError("chunk_size must be at least 4096")
    if not source.is_file():
        raise ValueError(f"input does not exist or is not a regular file: {source}")


def _read_key(args: argparse.Namespace) -> bytes:
    try:
        key = (
            bytes.fromhex(args.key_hex)
            if args.key_hex is not None
            else args.key_file.read_bytes()
        )
    except ValueError as exc:
        raise ValueError("--key-hex must be a valid hexadecimal string") from exc
    if len(key) != 32:
        raise ValueError("the ChaCha20 key must contain exactly 32 bytes")
    return key


def _key_header(key: bytes) -> str:
    values = ", ".join(f"0x{value:02x}" for value in key)
    return (
        "#pragma once\n\n#include <array>\n#include <cstdint>\n\n"
        "namespace embedded_key {\n"
        f"inline constexpr std::array<std::uint8_t, {len(key)}> kKey{{{{{values}}}}};\n"
        "}  // namespace embedded_key\n"
    )


def _cpp_string_literal(text: str) -> str:
    """Return concatenated C++ string literals with no token containing '??'."""
    if not text:
        return '""'

    segments: list[str] = []
    current: list[str] = []
    for char in text:
        if char == "?" and current and current[-1] == "?":
            segments.append("".join(current))
            current = [char]
        else:
            current.append(char)
    if current:
        segments.append("".join(current))
    return "".join(f'"{segment}"' for segment in segments)


class _Base85LiteralWriter:
    def __init__(self, header: TextIO, chars_per_literal: int) -> None:
        if chars_per_literal <= 0 or chars_per_literal % 5 != 0:
            raise ValueError("chars_per_literal must be a positive multiple of 5")
        self._header = header
        self._chars_per_literal = chars_per_literal
        self._raw_carry = b""
        self._encoded_buffer = bytearray()

    def write(self, data: bytes) -> None:
        if not data:
            return
        if self._raw_carry:
            data = self._raw_carry + data
        aligned = len(data) - (len(data) % 4)
        if aligned:
            self._encoded_buffer.extend(base64.b85encode(memoryview(data)[:aligned]))
            self._flush_full_literals()
        self._raw_carry = bytes(memoryview(data)[aligned:])

    def finish(self) -> None:
        if self._raw_carry:
            padded = self._raw_carry + (b"\0" * (4 - len(self._raw_carry)))
            self._encoded_buffer.extend(base64.b85encode(padded))
            self._raw_carry = b""
        self._flush_full_literals()
        if self._encoded_buffer:
            self._emit_literal(bytes(self._encoded_buffer))
            self._encoded_buffer.clear()

    def _flush_full_literals(self) -> None:
        while len(self._encoded_buffer) >= self._chars_per_literal:
            literal = bytes(self._encoded_buffer[: self._chars_per_literal])
            self._emit_literal(literal)
            del self._encoded_buffer[: self._chars_per_literal]

    def _emit_literal(self, literal: bytes) -> None:
        encoded = _cpp_string_literal(literal.decode("ascii"))
        self._header.write(f"    {encoded},\n")

def _write_base85_header(
    source: Path,
    output: Path,
    key: bytes,
    namespace: str,
    chunk_size: int,
) -> tuple[int, int, int, int]:
    original_size = source.stat().st_size
    encrypted_size = len(MAGIC) + 1 + 16 + original_size
    encoded_size = ((encrypted_size + 3) // 4) * 5
    count = (encoded_size + BASE85_CHARS_PER_LITERAL - 1) // BASE85_CHARS_PER_LITERAL
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    nonce = os.urandom(16)
    encryptor = Cipher(algorithms.ChaCha20(key=key, nonce=nonce), mode=None).encryptor()
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as header:
            temporary = Path(header.name)
            header.write(
                f"// Generated from {source.name}. Do not edit.\n#pragma once\n\n"
                "#include <array>\n#include <cstddef>\n#include <string_view>\n\n"
                f"namespace {namespace} {{\n\n"
                f'inline constexpr std::string_view kCipher = "ChaCha20";\n'
                'inline constexpr std::string_view kPipeline = "ChaCha20 -> Base85";\n'
                f"inline constexpr std::size_t kOriginalSize = {original_size};\n"
                f"inline constexpr std::size_t kEncryptedSize = {encrypted_size};\n"
                f"inline constexpr std::size_t kBase85EncodedSize = {encoded_size};\n"
                f"inline constexpr std::array<const char*, {count}> kBase85Payload{{{{\n"
            )
            writer = _Base85LiteralWriter(header, BASE85_CHARS_PER_LITERAL)
            writer.write(MAGIC + bytes((len(key),)) + nonce)
            with source.open("rb") as payload:
                while chunk := payload.read(chunk_size):
                    writer.write(encryptor.update(chunk))
            writer.write(encryptor.finalize())
            writer.finish()
            header.write(f"}}}};\n\n}}  // namespace {namespace}\n")
            header.flush()
            os.fsync(header.fileno())
        os.replace(temporary, output)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return original_size, encrypted_size, encoded_size, count


def encode(
    source: Path,
    output: Path,
    key: bytes,
    namespace: str = "liloaden_payload",
    chunk_size: int = CHUNK_SIZE,
) -> tuple[int, int, int, int]:
    _validate(source, namespace, chunk_size)
    if len(key) != 32:
        raise ValueError("the ChaCha20 key must contain exactly 32 bytes")
    return _write_base85_header(
        source=source,
        output=output,
        key=key,
        namespace=namespace,
        chunk_size=chunk_size,
    )


def encode_from_cli(
    args: argparse.Namespace,
    source: Path,
    output: Path,
    namespace: str,
) -> EncoderArtifacts:
    """Resolve this encoder's CLI settings and generate its payload artifacts."""
    from . import EncoderArtifacts

    key = _read_key(args)
    encode(
        source=source,
        output=output,
        key=key,
        namespace=namespace,
        chunk_size=args.chunk_size,
    )
    return EncoderArtifacts(headers={"payload_key.h": _key_header(key)})


CPP_DECODER_HEADER = r'''#pragma once

#include <cstddef>

namespace embedded {

class PayloadBuffer {
public:
    explicit PayloadBuffer(std::size_t size);
    ~PayloadBuffer();

    PayloadBuffer(const PayloadBuffer&) = delete;
    PayloadBuffer& operator=(const PayloadBuffer&) = delete;
    PayloadBuffer(PayloadBuffer&& other) noexcept;
    PayloadBuffer& operator=(PayloadBuffer&& other) noexcept;

    char* data() noexcept { return static_cast<char*>(data_); }
    const char* data() const noexcept { return static_cast<const char*>(data_); }
    std::size_t size() const noexcept { return size_; }

private:
    void* data_ = nullptr;
    std::size_t size_ = 0;
};

PayloadBuffer decode_payload(char*& data, std::size_t& size);

}  // namespace embedded
'''

CPP_DECODER_SOURCE = r'''#include "payload_decoder.h"

#include "payload.h"
#include "payload_key.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__linux__)
#include <sys/mman.h>
#else
#error "payload decoder supports only Windows and Linux"
#endif

namespace {

constexpr std::size_t kEnvelopeHeaderSize = 4 + 1 + 16;

void* allocate_rw(std::size_t size) {
    const std::size_t allocation_size = size == 0 ? 1 : size;
#if defined(_WIN32)
    void* memory = VirtualAlloc(
        nullptr, allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) throw std::runtime_error("VirtualAlloc failed");
#else
    void* memory = mmap(
        nullptr, allocation_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) throw std::runtime_error("mmap failed");
#endif
    return memory;
}

void release_rw(void* memory, std::size_t size) noexcept {
    if (!memory) return;
#if defined(_WIN32)
    VirtualFree(memory, 0, MEM_RELEASE);
#else
    munmap(memory, size == 0 ? 1 : size);
#endif
}

int base85_value(char ch) {
    static const std::array<int, 128> table = [] {
        std::array<int, 128> result{};
        result.fill(-1);
        constexpr std::string_view alphabet =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "!#$%&()*+-;<=>?@^_`{|}~";
        for (std::size_t index = 0; index < alphabet.size(); ++index) {
            result[static_cast<unsigned char>(alphabet[index])] = static_cast<int>(index);
        }
        return result;
    }();
    const unsigned char index = static_cast<unsigned char>(ch);
    if (index >= table.size() || table[index] < 0) {
        throw std::runtime_error("invalid Base85 digit");
    }
    return table[index];
}

std::vector<std::uint8_t> decode_base85_payload() {
    if (embedded_payload::kBase85EncodedSize % 5 != 0) {
        throw std::runtime_error("invalid Base85 payload size");
    }
    const std::size_t padded_size = (embedded_payload::kBase85EncodedSize / 5) * 4;
    if (padded_size < embedded_payload::kEncryptedSize) {
        throw std::runtime_error("truncated Base85 payload");
    }

    std::vector<std::uint8_t> result(padded_size);
    std::size_t offset = 0;
    for (const char* chunk_cstr : embedded_payload::kBase85Payload) {
        const std::string_view chunk(chunk_cstr);
        if (chunk.size() % 5 != 0) {
            throw std::runtime_error("misaligned Base85 chunk");
        }
        for (std::size_t index = 0; index < chunk.size(); index += 5) {
            std::uint64_t value = 0;
            for (std::size_t digit = 0; digit < 5; ++digit) {
                value = value * 85u + static_cast<std::uint64_t>(base85_value(chunk[index + digit]));
            }
            if (value > std::numeric_limits<std::uint32_t>::max()) {
                throw std::runtime_error("Base85 block overflow");
            }
            result[offset++] = static_cast<std::uint8_t>(value >> 24);
            result[offset++] = static_cast<std::uint8_t>(value >> 16);
            result[offset++] = static_cast<std::uint8_t>(value >> 8);
            result[offset++] = static_cast<std::uint8_t>(value);
        }
    }
    if (offset != result.size()) {
        throw std::runtime_error("truncated Base85 decode");
    }
    result.resize(embedded_payload::kEncryptedSize);
    return result;
}

void check_openssl(int status, const char* message) {
    if (status != 1) throw std::runtime_error(message);
}

void decrypt_envelope(
    const std::vector<std::uint8_t>& envelope, char* output, std::size_t output_size) {
    if (embedded_key::kKey.size() != 32) {
        throw std::runtime_error("ChaCha20 requires a 32-byte key");
    }
    if (envelope.size() < kEnvelopeHeaderSize ||
        envelope[0] != 'L' || envelope[1] != 'I' ||
        envelope[2] != 'L' || envelope[3] != '4') {
        throw std::runtime_error("invalid encrypted envelope");
    }
    if (envelope[4] != embedded_key::kKey.size()) {
        throw std::runtime_error("ChaCha20 key size does not match payload");
    }
    const std::size_t ciphertext_size = envelope.size() - kEnvelopeHeaderSize;
    if (ciphertext_size != output_size) {
        throw std::runtime_error("decoded payload size mismatch");
    }
    if (ciphertext_size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("encrypted payload exceeds OpenSSL one-call limit");
    }

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("cannot allocate OpenSSL context");
    struct Guard {
        EVP_CIPHER_CTX* context;
        ~Guard() { EVP_CIPHER_CTX_free(context); }
    } guard{raw};

    check_openssl(
        EVP_DecryptInit_ex(raw, EVP_chacha20(), nullptr,
            embedded_key::kKey.data(), envelope.data() + 5),
        "ChaCha20 init failed");
    int length = 0;
    check_openssl(
        EVP_DecryptUpdate(raw, reinterpret_cast<unsigned char*>(output), &length,
            envelope.data() + kEnvelopeHeaderSize, static_cast<int>(ciphertext_size)),
        "ChaCha20 decrypt failed");
    int final_length = 0;
    check_openssl(
        EVP_DecryptFinal_ex(raw, reinterpret_cast<unsigned char*>(output) + length, &final_length),
        "ChaCha20 finalize failed");
    if (static_cast<std::size_t>(length + final_length) != output_size) {
        throw std::runtime_error("decoded payload size mismatch");
    }
}

}  // namespace

namespace embedded {

PayloadBuffer::PayloadBuffer(std::size_t size) : data_(allocate_rw(size)), size_(size) {}

PayloadBuffer::~PayloadBuffer() { release_rw(data_, size_); }

PayloadBuffer::PayloadBuffer(PayloadBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

PayloadBuffer& PayloadBuffer::operator=(PayloadBuffer&& other) noexcept {
    if (this != &other) {
        release_rw(data_, size_);
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

PayloadBuffer decode_payload(char*& data, std::size_t& size) {
    auto envelope = decode_base85_payload();
    PayloadBuffer payload(embedded_payload::kOriginalSize);
    decrypt_envelope(envelope, payload.data(), payload.size());
    data = payload.data();
    size = payload.size();
    return payload;
}

}  // namespace embedded
'''


def cpp_decoder(namespace: str) -> CppDecoder:
    """Return this format's self-contained C++ decoder and build dependencies."""
    if namespace != "embedded_payload":
        raise ValueError("the chacha20-base85 C++ template currently requires the embedded_payload namespace")
    from . import CppDecoder

    return CppDecoder(
        header=CPP_DECODER_HEADER,
        source=CPP_DECODER_SOURCE,
        cmake_packages=("find_package(OpenSSL REQUIRED COMPONENTS Crypto)",),
        cmake_libraries=("OpenSSL::Crypto",),
    )


__all__ = [
    "BASE85_CHARS_PER_LITERAL",
    "CHUNK_SIZE",
    "CLI_EPILOG",
    "NAME",
    "add_cli_arguments",
    "cpp_decoder",
    "encode",
    "encode_from_cli",
]
