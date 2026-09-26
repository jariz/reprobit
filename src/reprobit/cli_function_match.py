"""Cold compilation and scoped byte comparison for one MSVC 7.1 leaf."""

from __future__ import annotations

import argparse
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from reprobit.cli_output import CLIOutput
from reprobit.function_match import match_function
from reprobit.model import Digest
from reprobit.msvc71 import MSVC71_FILES, authenticate_msvc71
from reprobit.process import CommandSpec, ProcessSupervisor
from reprobit.strict_json import canonical_json


def command_match_function(args: argparse.Namespace, output: CLIOutput) -> int:
    source = Path(args.source).resolve(strict=True)
    reference = Path(args.reference).resolve(strict=True)
    report_path = Path(args.report).resolve()
    if report_path in (source, reference) or report_path.exists():
        raise ValueError("report must be a new path, distinct from source and reference")
    toolchain = authenticate_msvc71(Path(args.toolchain_root))
    payload = source.read_bytes()
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() not in {"cl", "_cl_", "include", "lib", "libpath"}
    }
    environment["WINEDEBUG"] = "-all"
    options = ("/nologo", "/c", "/O1", "/Focandidate.obj")
    compiler = str(toolchain.host_path(toolchain.profile.compiler))
    launcher: tuple[str, ...] = ()
    if args.wine:
        launcher = (str(Path(args.wine).resolve(strict=True)),)
        if args.bottle:
            launcher += ("--bottle", args.bottle)
    elif args.bottle or os.name != "nt":
        raise ValueError("POSIX requires --wine; --bottle requires a CrossOver --wine launcher")
    command = (*launcher, compiler, *options, "unit.cpp")
    output.emit("function_compile", "Compiling one leaf with MSVC 13.10.3077 /O1")
    # A fresh workspace prevents a stale object from satisfying this run.
    with tempfile.TemporaryDirectory(prefix="reprobit-leaf-") as temporary:
        workspace = Path(temporary).resolve()
        (workspace / "unit.cpp").write_bytes(payload)
        spec = CommandSpec.create(
            command,
            cwd=workspace,
            environment=environment,
            timeout_seconds=args.timeout,
            log_path=workspace / "compile.log",
        )
        with ProcessSupervisor() as supervisor:
            result = supervisor.run(spec)
        obj = workspace / "candidate.obj"
        if obj.is_symlink() or not obj.is_file():
            raise ValueError("compiler did not produce a regular candidate.obj")
        candidate = obj.read_bytes()
        authenticate_msvc71(toolchain.root)
        # Reference bytes enter only the comparison, after compiler execution.
        match = match_function(
            candidate,
            reference.read_bytes(),
            symbol=args.symbol,
            virtual_address=args.va,
            size=args.size,
            reference_sha256=args.reference_sha256,
        )
    report = {
        "schema_version": 1,
        "scope": "leaf-function-literal-comparison",
        "certification": False,
        "profile": toolchain.profile.identifier,
        "toolchain_revision": toolchain.profile.sources[0].revision,
        "toolchain_files": MSVC71_FILES,
        "source_sha256": Digest.from_bytes(payload).value,
        "compile_options": options,
        "command": command,
        "compiler_output": result.output.decode("utf-8", "replace"),
        "comparison": asdict(match),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("xb") as stream:
        stream.write(canonical_json(report))
    verdict = "EXACT" if match.exact else "MISMATCH"
    output.emit(
        "function_match",
        f"{verdict}: {match.matching_bytes}/{match.reference_size} reference bytes; "
        f"candidate {match.candidate_size} bytes. Function comparison only, not certification.\n"
        f"Report: {report_path}",
        report=report,
    )
    return 0 if match.exact else 1
