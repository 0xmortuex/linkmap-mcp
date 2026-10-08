# linkmap-mcp

**Ask an AI agent "why did this land *there*?" and get the whole chain.**

<!-- mcp-name: io.github.0xmortuex/linkmap-mcp -->

linkmap-mcp is an [MCP](https://modelcontextprotocol.io) server that explains the memory
layout of a linked binary: a kernel, firmware, or a bootloader. It reads the ELF, and if
you have them, the linker's **map file** (GNU ld *and* LLVM lld formats) and the **linker
script**. From those it answers the questions people usually spend an afternoon
cross-referencing by hand:

- *Why is `boot_count` at `0x20000000`, and why does my startup code have to copy it?*
- *What is eating my flash?*
- *What grew between yesterday's build and today's?*
- *Is anything overlapping, overflowing, or placed by accident?*

## What it looks like

Real output from the Cortex-M fixture in `tests/fixtures/embedded` (lld build):

```
> link_load fw firmware.elf map=firmware.map script=link.ld
Loaded 'fw': firmware-lld-v2.elf, firmware-lld-v2.map (lld map), link.ld
ARM 32-bit, 6 allocated sections, 5 LOAD segments, 16 symbols
regions: FLASH 92.7% used, RAM 57.2% used
3 things worth a look - call link_overlaps.

> link_where fw boot_count
boot_count = boot_count (object, 4 bytes) at 0x20000000
  1. came from input section .data.boot_count in main.o (0x20000000+0x4)
  2. which the script rule `*(.data*)` in .data (line 32) captured
  3. which is part of output section .data (0x20000000-0x20000023, initialised data), in LOAD segment [3] RW-
  4. which runs in region RAM (0x20000000+0x1000) because the script says `.data : {...} > RAM` (line 32)
  5. and is stored at LMA 0x8003b30 in FLASH (`AT> FLASH`, line 32): copy 0x24 bytes from 0x8003b30 to 0x20000000 at boot

> link_overlaps fw
COPY NEEDED: .data runs at 0x20000000 but is stored at 0x8003b30. Startup must copy 0x24 (36) bytes: memcpy(0x20000000, 0x8003b30, 0x24).
NEARLY FULL: FLASH is 92.7% used (1.17 KiB free). Biggest users: font_bitmap (13.67 KiB), log_banner (600 B), main (330 B)
ORPHANS: .ARM.extab.text.main - not named in the linker script; the linker placed them by heuristic. Name them (or /DISCARD/ them) so their placement is intentional.

> link_diff v1 fw
v1 -> fw:
Sections:
  .bss                       1024 ->     1280  (+256)
  .text                     14372 ->    15076  (+704)
Regions:
  FLASH       14484 ->    15188  (+704), now 92.7% full
  RAM          2088 ->     2344  (+256), now 57.2% full
New symbols: log_banner (+600), log_ring (+256)
Resized symbols: main (+102)
```

`link_where` also accepts addresses. Give it `0x8003874`, which is inside the FLASH copy
of `.data`, and it answers *"device_name … This is the LOAD IMAGE of .data"*.

## Why this exists

Linker map files hold every answer, but they're thousands of lines in two unrelated
formats. GNU ld's is free-form, with wrapped names and `*fill*` lines. lld's is a
fixed-width table. Neither connects back to the script rule that caused a placement.
Existing MCP servers for binaries are reverse-engineering tools (Ghidra, radare2,
disassemblers). They treat sections as a side detail, and none of them reads a map file or
a linker script.

## Install

```bash
pip install linkmap-mcp
claude mcp add linkmap -- linkmap-mcp
```

Other MCP clients use the same idea: run `linkmap-mcp` as a stdio server. Python 3.10+.
The only dependencies are `mcp` and `pyelftools`. No binutils are needed.

To get a map file, add `-Wl,-Map=out.map` to your link (or `-Map=out.map` when calling
`ld` directly). This works for GNU ld and lld alike.

## Tools

| Tool | What it does |
|------|--------------|
| `link_load` | Load an ELF under a name, optionally with `map=` and `script=`. Re-loading the same name replaces it. |
| `link_where` | **Why is it there:** object file and input section → the script rule that captured it → output section → LOAD segment → MEMORY region, plus the FLASH→RAM copy when LMA ≠ VMA. Accepts a symbol, `symbol+off`, a section, or an address (including one inside a load image). |
| `link_overlaps` | Overlapping sections (by VMA or stored bytes) and segments; sections outside or straddling regions; overflowing and ≥90%-full regions with their biggest users; RWX segments; orphan sections; discarded inputs; every copy loop startup code must do. |
| `link_biggest` | What is eating space, by `symbol`, `input` section, `object` file or `section`, optionally limited to one region. FLASH-resident load images count towards FLASH. |
| `link_diff` | Two builds compared: sections, region usage and symbols. |
| `link_layout` | LOAD segments with the sections in each (VMA, LMA, file and memory sizes), gaps, and region usage. |
| `link_script_explain` | A linker script in plain English: ENTRY, MEMORY, `> REGION` / `AT> REGION` / `AT()`, what each rule collects, KEEP, PROVIDE, ALIGN, `. =` moves, /DISCARD/. |
| `link_unload`, `link_sessions` | Housekeeping. |

## How "why" is worked out

- **Where things are** comes from the ELF: section VMAs, and LMAs derived from the program
  header that loads each section.
- **Which object it came from** comes from the map.
- **Which rule put it there:** GNU maps record the matching pattern (` *(.text*)`). For lld,
  the tool applies the linker's own algorithm to the script: the first input-section
  description in script order whose file and section patterns match wins. That covers
  `KEEP`, `EXCLUDE_FILE`, and `libfoo.a:member.o` patterns.
- **Orphans:** a section no rule matches is an *orphan*. Its placement came from the
  linker's heuristics, not from your script, and the tool says so.
- **Normalisation:** lld prints ARM Thumb function addresses with bit 0 set; GNU and the ELF
  section table don't. The tool normalises this, so `main` is `0x80000d0` with either
  linker.

## Limits

- **Script expressions:** the script parser handles the statements that decide placement.
  It doesn't evaluate arbitrary expressions. MEMORY values may use constants, `K`/`M`/`G`
  and `+ - * / << >>`; a symbol in `LENGTH =` is reported as an error rather than guessed.
  `OVERLAY`, `PHDRS` and `INSERT` are recognised but not modelled.
- **Map formats:** GNU ld and lld only. gold, mold, MSVC/LINK and the IAR/Keil formats aren't
  read yet (see [BACKLOG.md](BACKLOG.md)).
- **No map:** without a map, `link_where` still explains the output section, segment and
  region, but can't name the object file.

## Tests

```bash
pip install ".[test]" "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests && mypy --strict src
pytest tests
```

The fixtures are real link outputs, committed so the tests need no toolchain:
- an x86 multiboot kernel and a Cortex-M firmware (FLASH/RAM, `.data AT> FLASH`, KEEP,
  NOLOAD, PROVIDE, /DISCARD/, an orphan, plus a "v2" build that pushes FLASH to 92.7%)
- a deliberately overlapping layout

Each is linked with **both** lld (zig 0.16) and GNU ld 2.44.
`tests/fixtures/build_fixtures.py` rebuilds the lld set. CI's `gnu-ld` job relinks
everything with the GNU ld on the runner (`build_gnu.sh`) and checks that every symbol in
the fresh maps matches the ELF.

## License

MIT
