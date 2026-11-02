#!/usr/bin/env python3
"""Regenerate diagnostic prefix CRCs from an authenticated reference image.

SHA-256 values in runtime_profile.h remain the identity acceptance authority.
The generated CRC metadata only locates the first changed byte in a log line.
No executable or complete routine fixture is emitted by this generator.
"""

import argparse
import hashlib
from pathlib import Path
import re
import zlib

from run_native_validation import EXE_SHA256, extract_rva


def generate(profiles, read):
    lines = [
        "#pragma once", "",
        "// Generated diagnostic metadata for the verified 1.10.163 profile.",
        "// Prefix CRCs locate the FIRST differing byte; SHA-256 still decides identity.",
        "// Regenerate with tests/generate_runtime_fingerprints.py and your reference exe.",
        "#include <array>", "#include <cstdint>", "", "namespace freezefix {",
    ]
    for name, rva, length, expected in profiles:
        data = read(name, rva, length)
        if len(data) != length or hashlib.sha256(data).digest() != expected:
            raise ValueError(f"{name}: reference routine length/SHA-256 mismatch")
        crc = 0
        values = []
        for byte in data:
            crc = zlib.crc32(bytes([byte]), crc)
            values.append(crc)
        lines.append(f"inline constexpr std::array<std::uint32_t, {length}> kPrefixCrc_{name}" + "{{")
        for start in range(0, len(values), 8):
            lines.append("    " + ", ".join(f"0x{value:08X}u" for value in values[start:start + 8]) + ",")
        lines.append("}};")
    lines.append("} // namespace freezefix")
    return "\n".join(lines) + "\n"


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--exe", type=Path, help="matching unpacked reference executable")
    inputs.add_argument("--routines", type=Path,
                        help="directory of exact <profile-name>.bin routine extracts")
    parser.add_argument("--check", action="store_true", help="verify the checked-in header without modifying it")
    args = parser.parse_args()
    source = (root / "src/runtime_profile.h").read_text(encoding="utf-8")
    pattern = re.compile(r'\{"([a-z_]+)",\s*(0x[\dA-Fa-f]+),\s*(0x[\dA-Fa-f]+),\s*\{\{([^}]+)\}\}')
    profiles = []
    for name, rva, length, digest in pattern.findall(source):
        expected = bytes(int(value, 16) for value in re.findall(r"0x([\dA-Fa-f]{2})\b", digest))
        if len(expected) != 32:
            parser.error(f"invalid SHA-256 profile for {name}")
        profiles.append((name, int(rva, 16), int(length, 16), expected))
    if len(profiles) != 5:
        parser.error("expected exactly five supported runtime profiles")
    if args.exe:
        image = args.exe.read_bytes()
        if hashlib.sha256(image).hexdigest() != EXE_SHA256:
            parser.error("reference executable SHA-256 mismatch")

        def read(_name, rva, length):
            return extract_rva(image, rva, length)
    else:
        def read(name, _rva, length):
            return (args.routines / f"{name}.bin").read_bytes()[:length]
    try:
        result = generate(profiles, read)
    except ValueError as error:
        parser.error(str(error))
    destination = root / "src/runtime_fingerprints.h"
    if args.check:
        if destination.read_text(encoding="utf-8") != result:
            parser.error("checked-in diagnostic fingerprints differ from the verified reference")
        print("PASS: all five diagnostic fingerprint arrays match their SHA-256-verified reference routines")
    else:
        destination.write_text(result, encoding="utf-8")
        print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
