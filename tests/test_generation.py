from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from liloaden.payload_encoder import encode_file
from liloaden.encoder import available_encoders, encode
from liloaden.project_generator import main


KEY_HEX = "00112233445566778899aabbccddeeff"


class GenerationTests(unittest.TestCase):
    def test_encoder_registry_dispatches_to_common_entry_point(self) -> None:
        self.assertIn("lzma-aes-ipv6", available_encoders())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "payload.h"
            source.write_bytes(b"registry dispatch test")
            result = encode(
                "lzma-aes-ipv6", source, output, bytes.fromhex(KEY_HEX), chunk_size=4096
            )
            self.assertEqual(result[0], source.stat().st_size)
            self.assertTrue(output.is_file())

    def test_encode_file_writes_payload_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            output = root / "payload.h"
            source.write_bytes(b"LiLoaden test payload" * 32)

            original_size, _, compressed_size, count = encode_file(
                source, output, bytes.fromhex(KEY_HEX), chunk_size=4096
            )

            header = output.read_text(encoding="utf-8")
            self.assertEqual(original_size, source.stat().st_size)
            self.assertIn(f"kOriginalSize = {original_size}", header)
            self.assertIn(f"kCompressedSize = {compressed_size}", header)
            self.assertIn(f"array<const char*, {count}>", header)

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

            generated_main = (output / "src/main.cpp").read_text(encoding="utf-8")
            self.assertNotIn("std::cout", generated_main)
            self.assertNotIn("std::cerr", generated_main)
            self.assertNotIn("<iostream>", generated_main)

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
