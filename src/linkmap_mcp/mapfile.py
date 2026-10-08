"""Parse GNU ld and LLVM lld map files into one model.

The two formats share nothing but intent.

lld (`-Map=`) is a fixed-width table; indentation of the last column says
what a row is (output section / input section / symbol):

         VMA      LMA     Size Align Out     In      Symbol
      100000   100000       d1    16 .text
      100000   100000        c     4         boot.o:(.multiboot)
      10000c   10000c        0     1                 _start

GNU ld (`-Map=`) is free-form: a Memory Configuration table, then output
sections at column 0 (with `load address` when LMA != VMA), input sections
indented by one space, symbols and script assignments indented by 16, the
script's input patterns (` *(.text*)`), `*fill*` padding, and long names
wrapped onto their own line:

    .text           0x00100000       0x98
     *(.text*)
     .text.triple_fault
                    0x0010005e        0xf kernel.o
                    0x0010005e                triple_fault
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


@dataclass
class MapSymbol:
    name: str
    address: int


@dataclass
class InputSection:
    name: str  # .text.kmain
    file: str  # kernel.o, libc.a(memcpy.o), "linker stubs", <internal>
    vma: int
    lma: int
    size: int
    symbols: list[MapSymbol] = field(default_factory=list)
    pattern: str | None = None  # GNU only: the script rule that matched it


@dataclass
class OutputSection:
    name: str
    vma: int
    lma: int
    size: int
    inputs: list[InputSection] = field(default_factory=list)
    assignments: list[tuple[int, str]] = field(default_factory=list)
    fill: int = 0  # bytes of *fill* padding (GNU)


@dataclass
class Region:
    name: str
    origin: int
    length: int
    attributes: str = ""

    @property
    def end(self) -> int:
        return self.origin + self.length

    def contains(self, address: int) -> bool:
        return self.origin <= address < self.end


@dataclass
class MapFile:
    path: str
    format: str  # "gnu" | "lld"
    sections: list[OutputSection] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    discarded: list[InputSection] = field(default_factory=list)
    top_assignments: list[tuple[int, str]] = field(default_factory=list)

    def inputs(self) -> list[tuple[OutputSection, InputSection]]:
        return [(o, i) for o in self.sections for i in o.inputs]

    def input_at(self, address: int) -> tuple[OutputSection, InputSection] | None:
        """The input section covering a VMA (smallest wins, zero-size skipped)."""
        best: tuple[OutputSection, InputSection] | None = None
        for o, i in self.inputs():
            if i.size and i.vma <= address < i.vma + i.size:
                if best is None or i.size < best[1].size:
                    best = (o, i)
        return best

    def symbol(self, name: str) -> tuple[OutputSection, InputSection, MapSymbol] | None:
        for o, i in self.inputs():
            for s in i.symbols:
                if s.name == name:
                    return o, i, s
        return None


def parse(path: str) -> MapFile:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"map file not found: {path}")
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    head = text.lstrip()[:200]
    if re.match(r"\s*VMA\s+LMA\s+Size\s+Align\s+Out\s+In\s+Symbol", head):
        return _parse_lld(path, text)
    if "Linker script and memory map" in text:
        return _parse_gnu(path, text)
    raise ValueError(
        f"{path} is not a GNU ld or lld map file I recognise. Produce one with "
        "-Wl,-Map=out.map (GNU ld or lld); gold and MSVC/LINK maps are not supported."
    )


# -- lld ---------------------------------------------------------------------

_LLD_ROW = re.compile(r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\d+) (.*)$")
_LLD_INPUT = re.compile(r"^(?P<file>.*):\((?P<sec>[^()]*?)(?:\+0x[0-9a-fA-F]+)?\)$")


def _parse_lld(path: str, text: str) -> MapFile:
    m = MapFile(path, "lld")
    lines = text.splitlines()
    header = lines[0]
    # Column of "Out"/"In"/"Symbol" text, from the header row.
    out_col = header.index("Out")
    in_col = header.index("In ", out_col)
    sym_col = header.index("Symbol")
    out: OutputSection | None = None
    inp: InputSection | None = None
    for line in lines[1:]:
        row = _LLD_ROW.match(line)
        if not row:
            continue
        vma, lma, size = (int(row.group(k), 16) for k in (1, 2, 3))
        rest_start = row.start(5)
        col = rest_start + (len(row.group(5)) - len(row.group(5).lstrip()))
        body = row.group(5).strip()
        if col < in_col:  # output-section level
            if "=" in body or body.startswith(("PROVIDE", "ASSERT")):
                m.top_assignments.append((vma, body))
                continue
            out = OutputSection(body, vma, lma, size)
            m.sections.append(out)
            inp = None
        elif col < sym_col:  # input-section level
            if out is None:
                continue
            im = _LLD_INPUT.match(body)
            if im:
                inp = InputSection(im.group("sec"), im.group("file"), vma, lma, size)
                out.inputs.append(inp)
            else:
                out.assignments.append((vma, body))
        else:  # symbol level
            if inp is not None and "=" not in body and not body.startswith("$"):
                inp.symbols.append(MapSymbol(body, vma))
            elif out is not None and "=" in body:
                out.assignments.append((vma, body))
    del out_col
    return m


# -- GNU ld --------------------------------------------------------------------

_HEX = r"0x([0-9a-fA-F]+)"
_GNU_OUT = re.compile(rf"^(\S+)\s+{_HEX}\s+{_HEX}(?:\s+load address {_HEX})?\s*$")
_GNU_OUT_WRAPPED = re.compile(rf"^\s+{_HEX}\s+{_HEX}(?:\s+load address {_HEX})?\s*$")
_GNU_IN = re.compile(rf"^ (\S+)\s+{_HEX}\s+{_HEX}\s+(.+?)\s*$")
_GNU_IN_WRAPPED = re.compile(rf"^\s+{_HEX}\s+{_HEX}\s+(.+?)\s*$")
_GNU_SYM = re.compile(rf"^\s{{16}}{_HEX}\s+(.+?)\s*$")
_GNU_FILL = re.compile(rf"^ \*fill\*\s+{_HEX}\s+{_HEX}")
_GNU_REGION = re.compile(rf"^(\S+)\s+{_HEX}\s+{_HEX}(?:\s+(\S+))?\s*$")


def _is_assignment(text: str) -> bool:
    return "=" in text or text.startswith(("PROVIDE", "ASSERT", "ALIGN"))


def _parse_gnu(path: str, text: str) -> MapFile:
    m = MapFile(path, "gnu")
    lines = text.splitlines()
    i = 0
    n = len(lines)

    # Discarded input sections / Memory Configuration come before the map.
    mode = ""
    pending_name: str | None = None
    while i < n and lines[i].strip() != "Linker script and memory map":
        line = lines[i]
        s = line.strip()
        if s == "Discarded input sections":
            mode = "discarded"
        elif s == "Memory Configuration":
            mode = "memory"
        elif mode == "memory":
            r = _GNU_REGION.match(line)
            if r and r.group(1) != "Name":
                if r.group(1) != "*default*":
                    m.regions.append(Region(r.group(1), int(r.group(2), 16),
                                            int(r.group(3), 16), r.group(4) or ""))
        elif mode == "discarded":
            im = _GNU_IN.match(line)
            if im:
                m.discarded.append(InputSection(im.group(1), im.group(4).strip(),
                                                0, 0, int(im.group(3), 16)))
            elif line.startswith(" ") and not line.startswith("  ") and len(s.split()) == 1:
                pending_name = s
            elif pending_name:
                w = _GNU_IN_WRAPPED.match(line)
                if w:
                    m.discarded.append(InputSection(pending_name, w.group(3).strip(), 0, 0,
                                                    int(w.group(2), 16)))
                pending_name = None
        i += 1
    i += 1

    out: OutputSection | None = None
    inp: InputSection | None = None
    pattern: str | None = None
    pending_out: str | None = None
    pending_in: str | None = None
    while i < n:
        line = lines[i]
        i += 1
        if not line.strip():
            continue
        if line.startswith(("LOAD ", "OUTPUT(", "START GROUP", "END GROUP")):
            continue
        if "(size before relaxing)" in line:
            continue
        if pending_out is not None:
            w = _GNU_OUT_WRAPPED.match(line)
            if w:
                out = _new_out(m, pending_out, w.group(1), w.group(2), w.group(3))
                inp, pattern = None, None
            pending_out = None
            if w:
                continue
        if pending_in is not None:
            w = _GNU_IN_WRAPPED.match(line)
            pending = pending_in
            pending_in = None
            if w and out is not None:
                inp = _new_in(out, pending, w.group(1), w.group(2), w.group(3), pattern)
                continue
        if not line.startswith(" "):
            # Column 0: an output section (maybe wrapped), or /DISCARD/.
            o = _GNU_OUT.match(line)
            if o:
                out = _new_out(m, o.group(1), o.group(2), o.group(3), o.group(4))
                inp, pattern = None, None
            elif len(line.split()) == 1:
                if line.strip() == "/DISCARD/":
                    out, inp = None, None
                else:
                    pending_out = line.strip()
            continue
        fill = _GNU_FILL.match(line)
        if fill:
            if out is not None:
                out.fill += int(fill.group(2), 16)
            continue
        sym = _GNU_SYM.match(line)
        if sym:
            addr = int(sym.group(1), 16)
            body = sym.group(2)
            if _is_assignment(body):
                (out.assignments if out is not None else m.top_assignments).append((addr, body))
            elif inp is not None:
                inp.symbols.append(MapSymbol(body, addr))
            continue
        s = line.strip()
        if line.startswith(" ") and not line.startswith("  ") and s.startswith(("*", "KEEP")) \
                or (line.startswith(" ") and "(" in s and s.endswith(")") and not s.startswith(".")
                    and "0x" not in s):
            pattern = s
            continue
        im = _GNU_IN.match(line)
        if im and out is not None:
            inp = _new_in(out, im.group(1), im.group(2), im.group(3), im.group(4), pattern)
            continue
        if line.startswith(" ") and not line.startswith("  ") and len(s.split()) == 1:
            pending_in = s
    return m


def _new_out(m: MapFile, name: str, vma: str, size: str, lma: str | None) -> OutputSection:
    v = int(vma, 16)
    o = OutputSection(name, v, int(lma, 16) if lma else v, int(size, 16))
    m.sections.append(o)
    return o


def _new_in(out: OutputSection, name: str, vma: str, size: str, file: str,
            pattern: str | None) -> InputSection:
    v = int(vma, 16)
    i = InputSection(name, file.strip(), v, out.lma + (v - out.vma), int(size, 16), pattern=pattern)
    out.inputs.append(i)
    return i
