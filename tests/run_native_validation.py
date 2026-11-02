#!/usr/bin/env python3
"""Run original 1.10.163 insertion/lookup code against synthetic index data.

This optional Linux x86-64 check needs a legally obtained, matching unpacked
executable, or the two exact routine extracts. It never starts Fallout 4 and
does not access game data or saves. No Bethesda machine code is distributed.
"""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shlex
import struct
import subprocess
import tempfile


EXE_SHA256 = "9a147a35686691ac6c52c2b3bc24027fc26119c2eb77716e10900af29a61609e"
ROUTINES = (
    ("hash-routine.bin", 0x1B772F0, 0x16A,
     "4810170d9d4caaf6ce750980168bbcf25d30a8eb73a9c772f2810d15007479f3"),
    ("archive-find.bin", 0x1B78AF0, 0xFE,
     "f4172a68a14be8e48a1117fc70c1200f78623827f0ae64826742d890a6409895"),
)


def extract_rva(image, rva, length):
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[:2] != b"MZ" or image[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE image")
    count = struct.unpack_from("<H", image, pe + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe + 20)[0]
    sections = pe + 24 + optional_size
    for number in range(count):
        offset = sections + number * 40
        virtual_size, virtual_rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, offset + 8)
        relative = rva - virtual_rva
        if 0 <= relative and relative + length <= min(virtual_size, raw_size):
            start = raw_offset + relative
            result = image[start:start + length]
            if len(result) != length:
                raise ValueError("truncated routine")
            return result
    raise ValueError(f"routine RVA {rva:#x} is outside file-backed sections")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--exe", type=Path, help="matching unpacked Fallout4.exe")
    inputs.add_argument("--routines", type=Path,
                        help="directory containing the two verified routine extracts")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        parser.error("this optional harness requires Linux x86-64 and a C++17 compiler")

    image = None
    if args.exe:
        image = args.exe.read_bytes()
        if hashlib.sha256(image).hexdigest() != EXE_SHA256:
            parser.error("executable SHA-256 does not match the documented reference; refusing execution")

    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="freezefix-native-") as scratch:
        scratch = Path(scratch)
        fixtures = []
        for name, rva, length, expected in ROUTINES:
            data = (extract_rva(image, rva, length) if image is not None
                    else (args.routines / name).read_bytes()[:length])
            if len(data) != length or hashlib.sha256(data).hexdigest() != expected:
                parser.error(f"{name} SHA-256 mismatch; refusing execution")
            destination = scratch / name
            destination.write_bytes(data)
            fixtures.append(str(destination))
        binary = scratch / "native_engine_check"
        compiler = shlex.split(os.environ.get("CXX", "g++"))
        macros = subprocess.run(compiler + ["-dM", "-E", "-x", "c++", "-"],
                                input="", text=True, capture_output=True, check=True,
                                timeout=30).stdout
        # Keep GCC's outgoing shadow-space offsets stable across mixed SysV /
        # ms_abi calls. GCC 13.3 otherwise generated a post-call stack-relative
        # comparison against the wrong field in the split-storage fixture.
        # Clang uses its own ABI lowering and does not accept this GCC option.
        abi_flags = (["-maccumulate-outgoing-args"]
                     if "#define __GNUC__ " in macros and "#define __clang__ " not in macros
                     else [])
        subprocess.run(compiler + [
            "-std=c++17", "-O2", "-UNDEBUG", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
        ] + abi_flags + [
            "-I", str(root / "src"), str(root / "tests/native_engine_check.cpp"),
            "-o", str(binary)], check=True, timeout=60)
        subprocess.run([str(binary)] + fixtures, check=True, timeout=30)


if __name__ == "__main__":
    main()
