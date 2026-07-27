"""Raw binary-to-IPv6-literal encoder and matching C++ decoder."""

from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import CppDecoder, EncoderArtifacts

NAME = "ipv6"
CLI_EPILOG = "Example: %(prog)s input.bin generated-project --encoder ipv6"


def add_cli_arguments(parser: argparse.ArgumentParser) -> None:
    """The raw IPv6 encoder has no encoder-specific command-line options."""


def _validate(source: Path, namespace: str) -> None:
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not all(identifier.fullmatch(part) for part in namespace.split("::")):
        raise ValueError("namespace must be a valid C++ namespace")
    if not source.is_file():
        raise ValueError(f"input does not exist or is not a regular file: {source}")


def encode(
    source: Path,
    output: Path,
    namespace: str = "liloaden_payload",
) -> tuple[int, int]:
    """Convert each 16-byte input block to one expanded IPv6 address."""
    _validate(source, namespace)
    size = source.stat().st_size
    count = (size + 15) // 16
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8", newline="\n") as header:
        header.write(
            f"// Generated from {source.name}. Do not edit.\n#pragma once\n\n"
            "#include <array>\n#include <cstddef>\n\n"
            f"namespace {namespace} {{\n\n"
            f"inline constexpr std::size_t kOriginalSize = {size};\n"
            f"inline constexpr std::array<const char*, {count}> kIpv6Payload{{{{\n"
        )
        with source.open("rb") as payload:
            while block := payload.read(16):
                block += b"\0" * (16 - len(block))
                header.write(f'    "{ipaddress.IPv6Address(block).exploded}",\n')
        header.write(f"}}}};\n\n}}  // namespace {namespace}\n")
    return size, count


def encode_from_cli(
    args: argparse.Namespace,
    source: Path,
    output: Path,
    namespace: str,
) -> EncoderArtifacts:
    from . import EncoderArtifacts

    encode(source=source, output=output, namespace=namespace)
    return EncoderArtifacts(headers={})


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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string_view>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__linux__)
#include <sys/mman.h>
#else
#error "payload decoder supports only Windows and Linux"
#endif

namespace {

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
    PayloadBuffer payload(embedded_payload::kOriginalSize);
    std::size_t offset = 0;
    for (const char* address : embedded_payload::kIpv6Payload) {
        const auto block = parse_ipv6(address);
        const std::size_t count = std::min(block.size(), payload.size() - offset);
        if (count != 0) std::memcpy(payload.data() + offset, block.data(), count);
        offset += count;
    }
    if (offset != payload.size()) throw std::runtime_error("truncated IPv6 payload");
    data = payload.data();
    size = payload.size();
    return payload;
}

}  // namespace embedded
'''


def cpp_decoder(namespace: str) -> CppDecoder:
    if namespace != "embedded_payload":
        raise ValueError("the ipv6 C++ template currently requires the embedded_payload namespace")
    from . import CppDecoder

    return CppDecoder(header=CPP_DECODER_HEADER, source=CPP_DECODER_SOURCE)


__all__ = [
    "CLI_EPILOG",
    "NAME",
    "add_cli_arguments",
    "cpp_decoder",
    "encode",
    "encode_from_cli",
]
