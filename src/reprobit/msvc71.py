"""Authenticate the unmodified 13.10.3077 compiler used by leaf matching."""

from __future__ import annotations

from pathlib import Path

from reprobit.model import Digest
from reprobit.toolchains import MSVC_71, ClassicMSVCToolchain, ToolchainError

# Files from the immutable repository revision in the msvc_7_1 profile.
MSVC71_FILES = {
    "Vc7/bin/cl.exe": "2ecf86a3edfd3deae498e08298e210e984537ce9e11759930561e43f40bd2515",
    "Vc7/bin/c1.dll": "11f452af93f8e686b36b348763b33d32ae2766f1b0c360a447053bf44ec50fcc",
    "Vc7/bin/c1xx.dll": "353f3d5dcd050b876e1c044b99c4bf47958d255f395a4919f406a19921be4dfa",
    "Vc7/bin/c2.dll": "bcd28f39b1798b07989c30a1df471cf87fc20e3802d130901a08f83800e6b81e",
    "Vc7/bin/mspdb71.dll": "85ebd7dcbe1b9fa756f23e5f811d7dfeccdac0de14271f2c18affbf918d8cb79",
    "Vc7/bin/link.exe": "0d5f9712d0da843d787bf4ce4e678abc6b737940996706b2c86101eac9df3e3c",
    "Vc7/bin/lib.exe": "3892c55821f628961ebf177537fdb002f3423166ead89c3aa7bc2ea1419fe1eb",
    "Vc7/bin/rc.exe": "139597123a5daa11148da6704c779152dc6b693bde65222e6855639164aaf9bb",
    "Vc7/bin/cvtres.exe": "c08ec0a3053434a0ba017d50cf1fcd8a3bcc32cb67e43a2aefe3c01a41eedbf7",
    "Vc7/bin/msobj71.dll": "19ce191c44e783e70c762ef13c1e918fc07745c8f64fcfc7b217e73ef667c168",
    "Vc7/bin/rcdll.dll": "f0c29d72e249614ab801efc35de4fe939b3e7edd6d6f45c3df63f580c459f47c",
}


def authenticate_msvc71(root: Path) -> ClassicMSVCToolchain:
    toolchain = ClassicMSVCToolchain(MSVC_71, root.resolve(strict=True))
    toolchain.doctor().require_ok()
    for relative, expected in MSVC71_FILES.items():
        if Digest.from_path(toolchain.host_path(relative)).value != expected:
            raise ToolchainError(f"MSVC 7.1 file differs from pinned revision: {relative}")
    return toolchain
