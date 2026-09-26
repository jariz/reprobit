from __future__ import annotations

import io
import json
import os
import struct
from pathlib import Path

import pytest

from reprobit.binary import ByteIdentityError
from reprobit.cli import main
from reprobit.cli_function_match import command_match_function
from reprobit.cli_output import CLIOutput
from reprobit.function_match import leaf_function, match_function
from reprobit.model import Digest
from reprobit.msvc71 import MSVC71_FILES, authenticate_msvc71
from reprobit.toolchains import MSVC_71, ClassicMSVCToolchain, ToolchainError, profile


def object_file(body: bytes, *, relocation: bool = False, shared: bool = False) -> bytes:
    symbols = b"_leaf\0\0\0" + struct.pack("<IhHBB", 0, 1, 0x20, 2, 0)
    if shared:
        symbols += b"_other\0\0" + struct.pack("<IhHBB", 1, 1, 0x20, 2, 0)
    reloc = struct.pack("<IIH", 0, 0, 6) if relocation else b""
    header = struct.pack(
        "<HHIIIHH", 0x14C, 1, 0, 60 + len(body) + len(reloc), 2 if shared else 1, 0, 0
    )
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0,
        0,
        len(body),
        60,
        60 + len(body) if relocation else 0,
        0,
        int(relocation),
        0,
        0x60000020,
    )
    return header + section + body + reloc + symbols + struct.pack("<I", 4)


def image_file(body: bytes) -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x10F)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    for offset, value in ((28, 0x400000), (32, 0x1000), (36, 0x200), (56, 0x2000), (60, 0x200)):
        struct.pack_into("<I", data, optional + offset, value)
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        optional + 224,
        b".text\0\0\0",
        len(body),
        0x1000,
        len(body),
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    return bytes(data) + body


@pytest.mark.parametrize(
    "body,exact,matches",
    [(b"ABCD", True, 4), (b"ABcD", False, 3), (b"ABCDX", False, 4), (b"ABC", False, 3)],
)
def test_literal_match_checks_complete_length(body: bytes, exact: bool, matches: int) -> None:
    reference = image_file(b"ABCD")
    result = match_function(
        object_file(body),
        reference,
        symbol="_leaf",
        virtual_address=0x401000,
        size=4,
        reference_sha256=Digest.from_bytes(reference).value,
    )
    assert result.exact is exact
    assert result.matching_bytes == matches
    assert result.candidate_size == len(body)


def test_wrong_reference_rejected() -> None:
    with pytest.raises(ByteIdentityError, match="SHA-256"):
        match_function(
            object_file(b"ABCD"),
            image_file(b"ABCD"),
            symbol="_leaf",
            virtual_address=0x401000,
            size=4,
            reference_sha256="0" * 64,
        )


@pytest.mark.parametrize("address,size", [(0x401000, 0), (0x401000, 5), (0x400FFF, 4)])
def test_reference_range_must_be_file_backed(address: int, size: int) -> None:
    reference = image_file(b"ABCD")
    with pytest.raises(ByteIdentityError):
        match_function(
            object_file(b"ABCD"),
            reference,
            symbol="_leaf",
            virtual_address=address,
            size=size,
            reference_sha256=Digest.from_bytes(reference).value,
        )


def test_relocations_and_shared_sections_rejected() -> None:
    with pytest.raises(ByteIdentityError, match="relocated"):
        leaf_function(object_file(b"ABCD", relocation=True), "_leaf")
    with pytest.raises(ByteIdentityError, match="shares"):
        leaf_function(object_file(b"ABCD", shared=True), "_leaf")
    with pytest.raises(ByteIdentityError, match="defined function"):
        leaf_function(object_file(b"ABCD"), "_missing")


def test_msvc71_profile_and_lock(tmp_path: Path) -> None:
    selected = profile(MSVC_71)
    assert selected.sources[0].revision == "2932d76fe417b0bc49010b26d4be2e5b743cc4be"
    assert set(MSVC71_FILES) == set(selected.required_producers + selected.required_runtime_files)
    for relative in MSVC71_FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"not the compiler")
    for relative in selected.include_roots + selected.library_roots:
        (tmp_path / relative).mkdir(parents=True)
    toolchain = ClassicMSVCToolchain(MSVC_71, tmp_path)
    lock = toolchain.create_lock()
    assert lock.release == "7.1"
    assert (
        toolchain.default_environment(temp_directory=r"R:\temp")["PATH"] == r"R:\toolchain\Vc7\bin"
    )
    with pytest.raises(ToolchainError, match="pinned revision"):
        authenticate_msvc71(tmp_path)


def test_cli_rejects_overwriting_inputs(tmp_path: Path) -> None:
    source = tmp_path / "unit.cpp"
    source.write_text("int leaf() { return 7; }")
    from argparse import Namespace

    args = Namespace(source=str(source), reference=str(source), report=str(source))
    with pytest.raises(ValueError, match="new path"):
        command_match_function(args, CLIOutput("text", io.StringIO(), io.StringIO()))
    assert source.read_text() == "int leaf() { return 7; }"


def test_real_msvc71_leaf(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = os.environ.get("REPROBIT_MSVC_7_1_ROOT")
    wine = os.environ.get("REPROBIT_MATCH_WINE")
    if not root or (os.name != "nt" and not wine):
        pytest.skip("requires MSVC 7.1 and a configured Wine launcher or native Windows")
    source = tmp_path / "unit.cpp"
    source.write_text('extern "C" int leaf() { return 7; }\n')
    reference = tmp_path / "reference.exe"
    reference.write_bytes(image_file(bytes.fromhex("6a0758c3")))
    report = tmp_path / "report.json"
    argv = [
        "match-function",
        str(source),
        "--toolchain-root",
        root,
        "--reference",
        str(reference),
        "--reference-sha256",
        Digest.from_path(reference).value,
        "--symbol",
        "_leaf",
        "--va",
        "0x401000",
        "--size",
        "4",
        "--report",
        str(report),
    ]
    if wine:
        argv += ["--wine", wine]
    if bottle := os.environ.get("REPROBIT_MATCH_BOTTLE"):
        argv += ["--bottle", bottle]
    assert main(argv) == 0, capsys.readouterr()
    document = json.loads(report.read_text())
    assert document["comparison"]["exact"]
    assert document["certification"] is False
    assert document["scope"] == "leaf-function-literal-comparison"
