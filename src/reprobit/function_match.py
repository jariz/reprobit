"""Literal leaf-function comparison, separate from whole-artifact certification."""

from __future__ import annotations

from dataclasses import dataclass

from reprobit.binary import require
from reprobit.coff_format import CoffObject, coff_body
from reprobit.formats import parse_pe32
from reprobit.model import Digest


@dataclass(frozen=True, slots=True)
class FunctionMatch:
    symbol: str
    virtual_address: int
    reference_size: int
    candidate_size: int
    matching_bytes: int
    exact: bool
    reference_sha256: str
    object_sha256: str
    reference_function_sha256: str
    candidate_function_sha256: str


def leaf_function(data: bytes, symbol: str) -> bytes:
    """Require an entire dedicated code section, never a matching prefix."""
    coff = CoffObject(data)
    definitions = [
        item
        for item in coff.symbols.values()
        if item["name"] == symbol
        and item["section"] > 0
        and item["type"] == 0x20
        and item["storage"] in (2, 3)
    ]
    require(len(definitions) == 1, "expected one defined function symbol")
    definition = definitions[0]
    require(definition["value"] == 0, "function must start its dedicated section")
    require(definition["section"] <= len(coff.sections), "invalid function section")
    section = coff.sections[definition["section"] - 1]
    require(bool(section["characteristics"] & 0x20), "function section is not code")
    require(section["relocation_count"] == 0, "relocated functions are not supported")
    functions = [
        item
        for item in coff.symbols.values()
        if item["section"] == definition["section"] and item["type"] == 0x20
    ]
    require(len(functions) == 1, "function shares its section with another function")
    body = coff_body(coff, section)
    require(bool(body), "function section is empty")
    return body


def match_function(
    candidate: bytes,
    reference: bytes,
    *,
    symbol: str,
    virtual_address: int,
    size: int,
    reference_sha256: str,
) -> FunctionMatch:
    require(Digest.from_bytes(reference).value == reference_sha256, "reference SHA-256 differs")
    require(size > 0, "reference function size must be positive")
    pe = parse_pe32(reference)
    rva = virtual_address - pe.image_base
    sections = [
        section
        for section in pe.sections
        if section.virtual_address <= rva
        and rva + size <= section.virtual_address + len(section.raw_data)
    ]
    require(len(sections) == 1, "reference function must fit in one file-backed section")
    section = sections[0]
    require(bool(section.characteristics & 0x20000000), "reference section is not executable")
    start = rva - section.virtual_address
    original = section.raw_data[start : start + size]
    rebuilt = leaf_function(candidate, symbol)
    return FunctionMatch(
        symbol,
        virtual_address,
        size,
        len(rebuilt),
        sum(a == b for a, b in zip(original, rebuilt, strict=False)),
        rebuilt == original,
        reference_sha256,
        Digest.from_bytes(candidate).value,
        Digest.from_bytes(original).value,
        Digest.from_bytes(rebuilt).value,
    )
