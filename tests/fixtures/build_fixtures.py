"""Rebuild the lld fixtures (committed, so tests need no toolchain).

Requires: pip install ziglang

The GNU ld fixtures (*-gnu.elf / *-gnu.map) were linked with GNU ld 2.44
from the same object files; CI regenerates them with the commands in
.github/workflows/ci.yml (job `gnu-ld`) and checks the parser against them.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ZIG = [sys.executable, "-m", "ziglang"]


def run(cwd: str, *args: str) -> None:
    subprocess.run([*ZIG, *args], check=True, cwd=os.path.join(HERE, cwd))


def x86() -> None:
    t = ["-target", "x86-freestanding-none"]
    run("x86", "cc", *t, "-ffreestanding", "-fno-pie", "-fno-stack-protector", "-O0", "-g",
        "-fno-omit-frame-pointer", "-fno-sanitize=undefined", "-ffunction-sections",
        "-fdata-sections", "-c", "kernel.c", "-o", "kernel.o")
    run("x86", "cc", *t, "-c", "boot.s", "-o", "boot.o")
    run("x86", "ld.lld", "-m", "elf_i386", "-T", "linker.ld", "--build-id=none",
        "-Map=kernel-lld.map", "-o", "kernel-lld.elf", "boot.o", "kernel.o")


def embedded(defines: list[str], suffix: str) -> None:
    t = ["-target", "thumb-freestanding-eabi", "-mcpu=cortex_m3"]
    for f in ("startup", "main"):
        run("embedded", "cc", *t, *defines, "-ffreestanding", "-O1", "-g",
            "-fno-sanitize=undefined", "-ffunction-sections", "-fdata-sections",
            "-c", f"{f}.c", "-o", f"{f}.o")
    run("embedded", "ld.lld", "-T", "link.ld", "--build-id=none", "-z", "max-page-size=0x100",
        f"-Map=firmware-lld{suffix}.map", "-o", f"firmware-lld{suffix}.elf", "startup.o", "main.o")


def overlap() -> None:
    # A broken script on purpose; --no-check-sections makes lld emit it anyway.
    t = ["-target", "x86-freestanding-none"]
    run("overlap", "cc", *t, "-ffreestanding", "-O0", "-fno-sanitize=undefined",
        "-ffunction-sections", "-fdata-sections", "-c", "prog.c", "-o", "prog.o")
    run("overlap", "ld.lld", "-m", "elf_i386", "-T", "overlap.ld", "--build-id=none",
        "--no-check-sections", "-Map=overlap.map", "-o", "overlap.elf", "prog.o")


def clean() -> None:
    for d in ("x86", "embedded", "overlap"):
        for f in os.listdir(os.path.join(HERE, d)):
            if f.endswith(".o"):
                os.remove(os.path.join(HERE, d, f))


if __name__ == "__main__":
    x86()
    embedded([], "")
    embedded(["-DV2"], "-v2")  # a bigger build, for link_diff
    overlap()
    clean()
    print("rebuilt lld fixtures")
