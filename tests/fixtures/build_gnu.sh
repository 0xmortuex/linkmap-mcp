#!/bin/sh
# Link the fixtures with GNU ld, as CI does (job `gnu-ld`) and as the committed
# *-gnu.elf / *-gnu.map files were made (GNU ld 2.44).
# Needs: binutils (ld), binutils-arm-none-eabi, and `pip install ziglang`
# for the compiler. Usage: build_gnu.sh OUTDIR
set -eu
OUT="$1"
HERE="$(cd "$(dirname "$0")" && pwd)"
ZIG="python -m ziglang"
mkdir -p "$OUT"

X86="-target x86-freestanding-none"
$ZIG cc $X86 -ffreestanding -fno-pie -fno-stack-protector -O0 -g -fno-omit-frame-pointer \
    -fno-sanitize=undefined -ffunction-sections -fdata-sections -c "$HERE/x86/kernel.c" -o "$OUT/kernel.o"
$ZIG cc $X86 -c "$HERE/x86/boot.s" -o "$OUT/boot.o"
ld -m elf_i386 -T "$HERE/x86/linker.ld" --build-id=none -Map="$OUT/kernel-gnu.map" \
    -o "$OUT/kernel-gnu.elf" "$OUT/boot.o" "$OUT/kernel.o"

ARM="-target thumb-freestanding-eabi -mcpu=cortex_m3"
for f in startup main; do
    $ZIG cc $ARM -ffreestanding -O1 -g -fno-sanitize=undefined -ffunction-sections \
        -fdata-sections -c "$HERE/embedded/$f.c" -o "$OUT/$f.o"
done
arm-none-eabi-ld -T "$HERE/embedded/link.ld" --build-id=none -z max-page-size=0x100 \
    -Map="$OUT/firmware-gnu.map" -o "$OUT/firmware-gnu.elf" "$OUT/startup.o" "$OUT/main.o"
echo "GNU ld fixtures in $OUT"
