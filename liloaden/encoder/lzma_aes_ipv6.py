"""LZMA -> AES-GCM -> LZMA encoder with IPv6-literal output."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING

from ..payload_encoder import CHUNK_SIZE, encode_file

if TYPE_CHECKING:
    from . import CppDecoder, EncoderArtifacts

NAME = "lzma-aes-ipv6"
CLI_EPILOG = (
    "Example: %(prog)s input.bin generated-project --encoder lzma-aes-ipv6 "
    "--key-hex 00112233445566778899aabbccddeeff"
)


def add_cli_arguments(parser: argparse.ArgumentParser) -> None:
    """Register arguments specific to the LZMA/AES/IPv6 encoding pipeline."""
    group = parser.add_argument_group(f"{NAME} options")
    keys = group.add_mutually_exclusive_group(required=True)
    keys.add_argument(
        "--key-hex",
        metavar="HEX",
        help="AES key as exactly 32, 48, or 64 hexadecimal characters",
    )
    keys.add_argument(
        "--key-file",
        type=Path,
        metavar="FILE",
        help="file containing exactly 16, 24, or 32 raw AES key bytes",
    )
    group.add_argument(
        "--chunk-size",
        type=int,
        default=CHUNK_SIZE,
        metavar="BYTES",
        help="streaming I/O chunk size; must be at least 4096 bytes",
    )
    group.add_argument(
        "--temp-dir",
        type=Path,
        metavar="DIR",
        help="intermediate-file directory (system temporary directory if omitted)",
    )


def _read_key(args: argparse.Namespace) -> bytes:
    try:
        key = (
            bytes.fromhex(args.key_hex)
            if args.key_hex is not None
            else args.key_file.read_bytes()
        )
    except ValueError as exc:
        raise ValueError("--key-hex must be a valid hexadecimal string") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError("the AES key must contain exactly 16, 24, or 32 bytes")
    return key


def _key_header(key: bytes) -> str:
    values = ", ".join(f"0x{value:02x}" for value in key)
    return (
        "#pragma once\n\n#include <array>\n#include <cstdint>\n\n"
        "namespace embedded_key {\n"
        f"inline constexpr std::array<std::uint8_t, {len(key)}> kKey{{{{{values}}}}};\n"
        "}  // namespace embedded_key\n"
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
        temp_dir=args.temp_dir.resolve() if args.temp_dir else None,
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

// Returns the owning buffer and exposes its borrowed pointer and byte count.
PayloadBuffer decode_payload(char*& data, std::size_t& size);

}  // namespace embedded
'''

CPP_DECODER_SOURCE = r'''#include "payload_decoder.h"

#include "payload.h"
#include "payload_key.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <lzma.h>
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

constexpr std::string_view kAad = "LiLoaden:LZMA:AES-GCM:LZMA:IPv6:v2";
constexpr std::size_t kEnvelopeHeaderSize = 4 + 1 + 12;
constexpr std::size_t kTagSize = 16;

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

int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    throw std::runtime_error("invalid IPv6 hex digit");
}

std::array<std::uint8_t, 16> parse_ipv6(std::string_view text) {
    std::array<std::uint8_t, 16> result{};
    std::size_t cursor = 0;
    for (std::size_t group = 0; group < 8; ++group) {
        if (cursor + 4 > text.size()) throw std::runtime_error("invalid IPv6 payload");
        const int a = hex_value(text[cursor]);
        const int b = hex_value(text[cursor + 1]);
        const int c = hex_value(text[cursor + 2]);
        const int d = hex_value(text[cursor + 3]);
        result[group * 2] = static_cast<std::uint8_t>((a << 4) | b);
        result[group * 2 + 1] = static_cast<std::uint8_t>((c << 4) | d);
        cursor += 4;
        if (group != 7) {
            if (cursor >= text.size() || text[cursor] != ':') {
                throw std::runtime_error("invalid IPv6 separator");
            }
            ++cursor;
        }
    }
    if (cursor != text.size()) throw std::runtime_error("invalid IPv6 length");
    return result;
}

std::vector<std::uint8_t> decode_ipv6_payload() {
    std::vector<std::uint8_t> result;
    result.reserve(embedded_payload::kIpv6Payload.size() * 16);
    for (const char* address : embedded_payload::kIpv6Payload) {
        const auto block = parse_ipv6(address);
        result.insert(result.end(), block.begin(), block.end());
    }
    if (result.size() < embedded_payload::kCompressedSize) {
        throw std::runtime_error("truncated IPv6 payload");
    }
    result.resize(embedded_payload::kCompressedSize);
    return result;
}

std::vector<std::uint8_t> decompress_xz(
    const std::vector<std::uint8_t>& input, std::size_t expected_size = 0) {
    lzma_stream stream = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&stream, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK) {
        throw std::runtime_error("cannot initialize LZMA decoder");
    }
    struct Guard {
        lzma_stream* stream;
        ~Guard() { lzma_end(stream); }
    } guard{&stream};

    stream.next_in = input.data();
    stream.avail_in = input.size();
    std::vector<std::uint8_t> output;
    if (expected_size) output.reserve(expected_size);
    std::array<std::uint8_t, 1024 * 1024> buffer{};
    while (true) {
        stream.next_out = buffer.data();
        stream.avail_out = buffer.size();
        const lzma_ret status = lzma_code(&stream, LZMA_FINISH);
        const std::size_t produced = buffer.size() - stream.avail_out;
        output.insert(output.end(), buffer.data(), buffer.data() + produced);
        if (status == LZMA_STREAM_END) break;
        if (status != LZMA_OK) throw std::runtime_error("LZMA decompression failed");
        if (produced == 0 && stream.avail_in == 0) {
            throw std::runtime_error("truncated LZMA stream");
        }
    }
    return output;
}

const EVP_CIPHER* aes_gcm_cipher(std::size_t key_size) {
    if (key_size == 16) return EVP_aes_128_gcm();
    if (key_size == 24) return EVP_aes_192_gcm();
    if (key_size == 32) return EVP_aes_256_gcm();
    throw std::runtime_error("invalid AES key size");
}

void check_openssl(int status, const char* message) {
    if (status != 1) throw std::runtime_error(message);
}

std::vector<std::uint8_t> decrypt_envelope(const std::vector<std::uint8_t>& envelope) {
    if (envelope.size() < kEnvelopeHeaderSize + kTagSize ||
        envelope[0] != 'L' || envelope[1] != 'I' ||
        envelope[2] != 'L' || envelope[3] != '2') {
        throw std::runtime_error("invalid encrypted envelope");
    }
    if (envelope[4] != embedded_key::kKey.size()) {
        throw std::runtime_error("AES key size does not match payload");
    }
    const std::size_t ciphertext_size = envelope.size() - kEnvelopeHeaderSize - kTagSize;
    if (ciphertext_size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("encrypted payload exceeds OpenSSL one-call limit");
    }

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("cannot allocate OpenSSL context");
    struct Guard {
        EVP_CIPHER_CTX* context;
        ~Guard() { EVP_CIPHER_CTX_free(context); }
    } guard{raw};

    const EVP_CIPHER* cipher = aes_gcm_cipher(embedded_key::kKey.size());
    check_openssl(EVP_DecryptInit_ex(raw, cipher, nullptr, nullptr, nullptr), "AES init failed");
    check_openssl(EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr), "AES IV init failed");
    check_openssl(EVP_DecryptInit_ex(raw, nullptr, nullptr, embedded_key::kKey.data(), envelope.data() + 5), "AES key init failed");
    int length = 0;
    check_openssl(EVP_DecryptUpdate(raw, nullptr, &length,
        reinterpret_cast<const unsigned char*>(kAad.data()), static_cast<int>(kAad.size())), "AES AAD failed");

    std::vector<std::uint8_t> plaintext(ciphertext_size + 16);
    check_openssl(EVP_DecryptUpdate(raw, plaintext.data(), &length,
        envelope.data() + kEnvelopeHeaderSize, static_cast<int>(ciphertext_size)), "AES decrypt failed");
    int total = length;
    std::array<std::uint8_t, kTagSize> tag{};
    std::copy_n(envelope.end() - kTagSize, kTagSize, tag.begin());
    check_openssl(EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_TAG, kTagSize, tag.data()), "AES tag init failed");
    check_openssl(EVP_DecryptFinal_ex(raw, plaintext.data() + total, &length), "AES-GCM authentication failed");
    total += length;
    plaintext.resize(static_cast<std::size_t>(total));
    return plaintext;
}

}  // namespace

namespace embedded {

PayloadBuffer::PayloadBuffer(std::size_t size) : data_(allocate_rw(size)), size_(size) {}

PayloadBuffer::~PayloadBuffer() {
    release_rw(data_, size_);
}

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
    auto outer_compressed = decode_ipv6_payload();
    auto envelope = decompress_xz(outer_compressed);
    outer_compressed.clear();
    outer_compressed.shrink_to_fit();

    auto inner_compressed = decrypt_envelope(envelope);
    envelope.clear();
    envelope.shrink_to_fit();

    auto bytes = decompress_xz(inner_compressed, embedded_payload::kOriginalSize);
    if (bytes.size() != embedded_payload::kOriginalSize) {
        throw std::runtime_error("decoded payload size mismatch");
    }
    PayloadBuffer payload(bytes.size());
    if (!bytes.empty()) {
        std::memcpy(payload.data(), bytes.data(), bytes.size());
    }
    data = payload.data();
    size = payload.size();
    return payload;
}

}  // namespace embedded
'''

def encode(
    source: Path,
    output: Path,
    key: bytes,
    namespace: str = "liloaden_payload",
    chunk_size: int = CHUNK_SIZE,
    temp_dir: Path | None = None,
) -> tuple[int, int, int, int]:
    return encode_file(source, output, key, namespace, chunk_size, temp_dir)


def cpp_decoder(namespace: str) -> CppDecoder:
    """Return this format's self-contained C++ decoder and build dependencies."""
    if namespace != "embedded_payload":
        raise ValueError("the lzma-aes-ipv6 C++ template currently requires the embedded_payload namespace")
    from . import CppDecoder

    return CppDecoder(
        header=CPP_DECODER_HEADER,
        source=CPP_DECODER_SOURCE,
        cmake_packages=(
            "find_package(OpenSSL REQUIRED COMPONENTS Crypto)",
            "find_package(LibLZMA REQUIRED)",
        ),
        cmake_libraries=("OpenSSL::Crypto", "LibLZMA::LibLZMA"),
    )


__all__ = [
    "CHUNK_SIZE",
    "CLI_EPILOG",
    "NAME",
    "add_cli_arguments",
    "cpp_decoder",
    "encode",
    "encode_from_cli",
]
