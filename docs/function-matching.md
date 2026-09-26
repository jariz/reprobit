# MSVC 7.1 leaf-function matching

The fork's `rbit match-function` command compiles one self-contained C++ source
with unmodified Visual C++ .NET 2003 (13.10.3077), then compares a named function's
complete code section with a pinned range in an owned PE32 executable.

```console
git clone https://github.com/archaic-msvc/msvc710.git /path/to/msvc710
git -C /path/to/msvc710 checkout --detach 2932d76fe417b0bc49010b26d4be2e5b743cc4be
rbit match-function leaf.cpp --toolchain-root /path/to/msvc710 \
  --reference /path/to/original.exe --reference-sha256 WHOLE_FILE_SHA256 \
  --symbol _leaf --va 0x401000 --size 4 --report leaf-report.json \
  --wine /path/to/wine
```

For CrossOver, point `--wine` at its `Contents/SharedSupport/CrossOver/bin/wine`
launcher and add `--bottle BOTTLE_NAME`. Omit both options on native Windows.
CrossOver uses the selected existing bottle; this command does not create the
private, sealed runtime used by certification. Its real-compiler integration
has been exercised with CrossOver on macOS; native Windows is not yet exercised
for this command.

The source is copied into a fresh temporary build directory. The compiler runs
with `/c /O1` and no inherited `CL`, `_CL_`, `INCLUDE`, `LIB`, or `LIBPATH`.
Pass a source that needs no project headers or linked runtime. Compiler tools
and support DLLs are checked against hashes from the profile's immutable
repository revision before and after compilation. Headers and libraries are
not authenticated by this command. Output and logs are temporary; the JSON
report records source/object/reference digests, compiler-file identities,
command, compiler output, and comparison scope.

The named function must start at offset zero in its own code section. Multiple
function symbols in the same section and code relocations are rejected. The
entire section is compared, including any padding: a matching prefix with extra
candidate bytes is a mismatch. The reference range must fit inside one
file-backed executable section. Callers remain responsible for establishing
the reference function's complete boundary and identity.

Exit codes: `0` for an exact match, `1` for a byte/length mismatch, `2` for an
invalid input or execution error. Reports use a new output path each time,
preventing accidental overwrite of inputs or previous evidence. `--format
ndjson` is supported as a global option.

## Evidence boundary

This is a literal function comparison, **not a certification**. Reports say
`scope: leaf-function-literal-comparison` and `certification: false`.
The compiler receives no reference path in its command, but it runs in an
ordinary user environment, not an isolated authenticity boundary. A match does
not prove source authenticity, absence of embedded bytes, behavior of other
functions, or whole-program identity. It does not invoke recipe interventions,
PDB rewriting, or `rbit verify`'s certification pipeline.

The `msvc_7_1` profile describes the repository layout, compiler/linker/SDK paths,
DLL frontend, and PDB generation. Existing profiles retain their previous
paths. The 4.2-specific recipe and compiler-identity proofs remain 4.2-specific;
this profile does not certify those transformations on 7.1. Automatic provisioning
and whole-program 7.1 certification are not implemented.

## Tests

The normal suite tests full-length comparison, reference identity, range bounds,
relocation/shared-section rejection, profile locking, and compiler tampering.
To run the public, synthetic real-compiler fixture through CrossOver:

```console
REPROBIT_MSVC_7_1_ROOT=/path/to/msvc710 \
REPROBIT_MATCH_WINE=/path/to/CrossOver/bin/wine \
REPROBIT_MATCH_BOTTLE=compiler-bottle \
python -m pytest -q tests/test_function_match.py
```
