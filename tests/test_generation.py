from __future__ import annotations

import ast
import base64
import contextlib
import io
import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from liloaden.payload_encoder import encode_file
from liloaden.encoder import CppDecoder, available_encoders, chacha20_base85, encode, get_encoder
from liloaden.project_generator import main, parse_args


KEY_HEX = "00112233445566778899aabbccddeeff"
CHACHA20_KEY_HEX = (
    "00112233445566778899aabbccddeeff"
    "00112233445566778899aabbccddeeff"
)


def _header_value(header: str, name: str) -> int:
    prefix = f"inline constexpr std::size_t {name} = "
    for line in header.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return int(stripped.removeprefix(prefix).rstrip(";"))
    raise AssertionError(f"missing header constant: {name}")


def _array_literals(header: str, array_name: str) -> list[str]:
    values: list[str] = []
    capture = False
    marker = f"{array_name}{{{{"
    for line in header.splitlines():
        stripped = line.strip()
        if marker in stripped:
            capture = True
            continue
        if capture:
            if stripped == "}};":
                break
            if stripped.startswith('"'):
                values.append(ast.literal_eval(stripped.removesuffix(',')))
    return values


class GenerationTests(unittest.TestCase):
    def test_encoder_registry_dispatches_to_common_entry_point(self) -> None:
        self.assertIn("chacha20-base85", available_encoders())
        self.assertIn("ipv6", available_encoders())
        self.assertIn("lzma-aes-ipv6", available_encoders())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "payload.h"
            source.write_bytes(b"registry dispatch test")
            result = encode(
                "chacha20-base85",
                source,
                output,
                key=bytes.fromhex(CHACHA20_KEY_HEX),
                chunk_size=4096,
            )
            self.assertEqual(result[0], source.stat().st_size)
            self.assertTrue(output.is_file())

    def test_ipv6_encoder_round_trips_raw_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "payload.h"
            expected = bytes(range(35))
            source.write_bytes(expected)

            size, count = encode("ipv6", source, output)

            addresses = []
            for line in output.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith('"'):
                    addresses.append(stripped.strip('",'))
            restored = b"".join(ipaddress.IPv6Address(item).packed for item in addresses)
            self.assertEqual(size, len(expected))
            self.assertEqual(count, 3)
            self.assertEqual(restored[:size], expected)

    def test_cpp_string_literal_splits_trigraph_prefixes(self) -> None:
        rendered = chacha20_base85._cpp_string_literal("A??!B????C")
        self.assertEqual(ast.literal_eval(rendered), "A??!B????C")
        for segment in rendered.split('""'):
            if segment.startswith('"') and segment.endswith('"'):
                self.assertNotIn("??", segment[1:-1])

    def test_chacha20_base85_encoder_round_trips_raw_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "payload.h"
            expected = bytes(range(251)) * 521
            key = bytes.fromhex(CHACHA20_KEY_HEX)
            source.write_bytes(expected)

            original_size, encrypted_size, encoded_size, count = encode(
                "chacha20-base85",
                source,
                output,
                key=key,
                chunk_size=4096,
            )

            header = output.read_text(encoding="utf-8")
            literals = _array_literals(header, "kBase85Payload")
            self.assertEqual(original_size, len(expected))
            self.assertEqual(_header_value(header, "kOriginalSize"), original_size)
            self.assertEqual(_header_value(header, "kEncryptedSize"), encrypted_size)
            self.assertEqual(_header_value(header, "kBase85EncodedSize"), encoded_size)
            self.assertEqual(len(literals), count)
            self.assertIn("ChaCha20 -> Base85", header)

            encoded = "".join(literals).encode("ascii")
            envelope = base64.b85decode(encoded)[:encrypted_size]
            self.assertEqual(envelope[:4], b"LIL4")
            self.assertEqual(envelope[4], len(key))

            nonce = envelope[5:21]
            ciphertext = envelope[21:]
            decryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
            restored = decryptor.update(ciphertext) + decryptor.finalize()
            self.assertEqual(restored, expected)

    def test_encoder_module_exposes_cpp_decoder_contract(self) -> None:
        encoder = get_encoder("chacha20-base85")
        decoder = encoder.cpp_decoder("embedded_payload")

        self.assertEqual(encoder.NAME, "chacha20-base85")
        self.assertIsInstance(decoder, CppDecoder)
        signature = "PayloadBuffer decode_payload(char*& data, std::size_t& size)"
        self.assertIn(signature, decoder.header)
        self.assertIn(signature, decoder.source)
        self.assertIn("find_package(OpenSSL REQUIRED COMPONENTS Crypto)", decoder.cmake_packages)
        self.assertIn("OpenSSL::Crypto", decoder.cmake_libraries)
        self.assertNotIn("LibLZMA::LibLZMA", decoder.cmake_libraries)
        self.assertTrue(callable(encoder.add_cli_arguments))
        self.assertTrue(callable(encoder.encode_from_cli))

    def test_project_cli_loads_selected_encoder_arguments(self) -> None:
        arguments = [
            "input.bin",
            "generated",
            "--encoder",
            "chacha20-base85",
            "--key-hex",
            CHACHA20_KEY_HEX,
            "--chunk-size",
            "8192",
        ]

        args = parse_args(arguments)

        self.assertEqual(args.encoder, "chacha20-base85")
        self.assertEqual(args.key_hex, CHACHA20_KEY_HEX)
        self.assertEqual(args.chunk_size, 8192)

        ipv6_args = parse_args(
            ["input.bin", "generated", "--encoder", "ipv6"]
        )
        self.assertEqual(ipv6_args.encoder, "ipv6")
        self.assertFalse(hasattr(ipv6_args, "key_hex"))

    def test_project_cli_help_groups_encoder_options(self) -> None:
        stream = io.StringIO()
        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stdout(stream):
            parse_args(["--encoder", "chacha20-base85", "--help"])

        self.assertEqual(raised.exception.code, 0)
        help_text = stream.getvalue()
        self.assertIn("Encoder-specific options are defined inside each encoder module", help_text)
        self.assertIn("[chacha20-base85 - selected]", help_text)
        self.assertIn("[lzma-aes-ipv6]", help_text)
        self.assertIn("[ipv6]", help_text)
        self.assertIn("(no encoder-specific options)", help_text)
        self.assertIn("--key-hex HEX", help_text)
        self.assertIn("--temp-dir DIR", help_text)

    def test_encode_file_writes_payload_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "payload.h"
            source.write_bytes(b"LiLoaden test payload" * 32)

            original_size, _, encrypted_size, count = encode_file(
                source, output, bytes.fromhex(KEY_HEX), chunk_size=4096
            )

            header = output.read_text(encoding="utf-8")
            self.assertEqual(original_size, source.stat().st_size)
            self.assertIn(f"kOriginalSize = {original_size}", header)
            self.assertIn(f"kEncryptedSize = {encrypted_size}", header)
            self.assertIn("LZMA/XZ -> AES-GCM -> IPv6", header)
            self.assertIn(f"array<const char*, {count}>", header)

            first_address = next(
                line.strip().strip('",')
                for line in header.splitlines()
                if line.strip().startswith('"')
            )
            self.assertEqual(ipaddress.IPv6Address(first_address).packed[:4], b"LIL3")

    def test_main_generates_raw_ipv6_project_without_crypto_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "generated"
            source.write_bytes(b"raw ipv6 project")
            arguments = [
                "generate_cmake_project.py",
                str(source),
                str(output),
                "--encoder",
                "ipv6",
            ]

            with patch.object(sys, "argv", arguments):
                self.assertEqual(main(), 0)

            self.assertFalse((output / "include/payload_key.h").exists())
            cmake = (output / "CMakeLists.txt").read_text(encoding="utf-8")
            self.assertNotIn("OpenSSL", cmake)
            self.assertNotIn("LibLZMA", cmake)
            self.assertNotIn("target_link_libraries(payload_decoder PRIVATE )", cmake)

    def test_main_generates_chacha20_base85_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "generated"
            source.write_bytes((b"project generation test for chacha20-base85" * 512)[:65537])
            arguments = [
                "generate_cmake_project.py",
                str(source),
                str(output),
                "--encoder",
                "chacha20-base85",
                "--key-hex",
                CHACHA20_KEY_HEX,
                "--chunk-size",
                "4096",
            ]

            with patch.object(sys, "argv", arguments):
                self.assertEqual(main(), 0)

            expected = {
                "CMakeLists.txt",
                "include/payload.h",
                "include/payload_key.h",
                "include/payload_decoder.h",
                "src/main.cpp",
                "src/payload_decoder.cpp",
            }
            actual = {
                str(path.relative_to(output))
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual, expected)

            generated_cmake = (output / "CMakeLists.txt").read_text(encoding="utf-8")
            self.assertIn("find_package(OpenSSL REQUIRED COMPONENTS Crypto)", generated_cmake)
            self.assertIn("OpenSSL::Crypto", generated_cmake)
            self.assertNotIn("LibLZMA", generated_cmake)

            payload_header = (output / "include/payload.h").read_text(encoding="utf-8")
            self.assertIn("ChaCha20 -> Base85", payload_header)
            self.assertIn("kBase85Payload", payload_header)

    def test_main_generates_expected_cmake_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "generated"
            source.write_bytes(b"project generation test")
            arguments = [
                "generate_cmake_project.py",
                str(source),
                str(output),
                "--key-hex",
                KEY_HEX,
                "--chunk-size",
                "4096",
            ]

            with patch.object(sys, "argv", arguments):
                self.assertEqual(main(), 0)

            expected = {
                "CMakeLists.txt",
                "include/payload.h",
                "include/payload_key.h",
                "include/payload_decoder.h",
                "src/main.cpp",
                "src/payload_decoder.cpp",
            }
            actual = {
                str(path.relative_to(output))
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual, expected)

            generated_cmake = (output / "CMakeLists.txt").read_text(
                encoding="utf-8"
            )
            self.assertIn("find_package(OpenSSL REQUIRED COMPONENTS Crypto)", generated_cmake)
            self.assertIn("find_package(LibLZMA REQUIRED)", generated_cmake)
            self.assertIn("OpenSSL::Crypto LibLZMA::LibLZMA", generated_cmake)
            self.assertIn('set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)', generated_cmake)
            self.assertIn('set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)', generated_cmake)
            self.assertIn('option(ENABLE_OLLVM "Enable OLLVM obfuscation', generated_cmake)
            self.assertIn('"-mllvm;-fla;-mllvm;-bcf;-mllvm;-sub"', generated_cmake)
            self.assertIn(
                "target_compile_options(payload_decoder PRIVATE ${OLLVM_COMPILE_OPTIONS})",
                generated_cmake,
            )
            self.assertIn('target_compile_options(payload_decoder PRIVATE "$<$<CONFIG:Release>:-g0>")', generated_cmake)
            self.assertIn('target_link_options(payload_decoder PRIVATE "$<$<CONFIG:Release>:-s>")', generated_cmake)

            generated_main = (output / "src/main.cpp").read_text(encoding="utf-8")
            self.assertNotIn("std::cout", generated_main)
            self.assertNotIn("std::cerr", generated_main)
            self.assertNotIn("<iostream>", generated_main)
            self.assertIn("decode_payload(data, size)", generated_main)
            self.assertIn("#include <thread>", generated_main)
            self.assertIn("std::thread payload_thread", generated_main)
            self.assertIn("payload_thread.join()", generated_main)

            generated_decoder = (output / "src/payload_decoder.cpp").read_text(
                encoding="utf-8"
            )
            self.assertIn("VirtualAlloc", generated_decoder)
            self.assertIn("PAGE_READWRITE", generated_decoder)
            self.assertIn("mmap", generated_decoder)
            self.assertIn("PROT_READ | PROT_WRITE", generated_decoder)
            self.assertNotIn("PAGE_EXECUTE", generated_decoder)
            self.assertNotIn("PROT_EXEC", generated_decoder)


if __name__ == "__main__":
    unittest.main()
