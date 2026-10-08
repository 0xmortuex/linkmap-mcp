"""Combine ELF + map file + linker script into answers.

ELF   -> where things ARE (sections, segments, symbols, VMA/LMA)
map   -> which object file and input section each byte came from
script-> which rule put it there, and in which MEMORY region
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from . import mapfile as mapmod
from . import script as scriptmod
from .elfinfo import ElfImage, Section
from .mapfile import InputSection, MapFile, OutputSection, Region
from .script import LinkerScript

NEARLY_FULL = 0.90


class LinkError(ValueError):
    """An expected, explainable problem with the inputs (bad query, missing file)."""


@dataclass
class RegionUse:
    region: Region
    vma_bytes: int  # address space used by sections that run here
    lma_bytes: int  # bytes stored here (incl. load images of sections that run elsewhere)
    sections: list[str]

    @property
    def used(self) -> int:
        return max(self.vma_bytes, self.lma_bytes)


class Linked:
    def __init__(self, name: str, elf: str, map_path: str | None = None, script_path: str | None = None):
        self.name = name
        self.elf = ElfImage(elf)
        self.map: MapFile | None = mapmod.parse(map_path) if map_path else None
        self.script: LinkerScript | None = scriptmod.parse(script_path) if script_path else None
        self._normalise_thumb()

    # -- setup -----------------------------------------------------------------

    def _normalise_thumb(self) -> None:
        """lld prints ARM Thumb function symbols with bit 0 set (main = 0x80000d1);
        GNU ld and the ELF section addresses don't. Clear it for code sections."""
        if self.map is None or self.elf.machine != "ARM":
            return
        for out, inp in self.map.inputs():
            if inp.name.startswith(".text"):
                for s in inp.symbols:
                    if s.address & 1 and inp.vma <= (s.address & ~1) < inp.vma + max(inp.size, 1):
                        s.address &= ~1

    @property
    def regions(self) -> list[Region]:
        if self.map is not None and self.map.regions:
            return self.map.regions
        if self.script is not None:
            return self.script.regions
        return []

    def region_of(self, address: int) -> Region | None:
        for r in self.regions:
            if r.contains(address):
                return r
        return None

    def sources(self) -> str:
        parts = [os.path.basename(self.elf.path)]
        if self.map:
            parts.append(f"{os.path.basename(self.map.path)} ({self.map.format} map)")
        if self.script:
            parts.append(os.path.basename(self.script.path))
        return ", ".join(parts)

    # -- region usage --------------------------------------------------------

    def region_usage(self) -> list[RegionUse]:
        uses = []
        for r in self.regions:
            vma = lma = 0
            names = []
            for s in self.elf.alloc_sections:
                runs_here = r.contains(s.addr)
                stored_here = not s.nobits and r.contains(s.lma)
                if runs_here:
                    vma += s.size
                if stored_here:
                    lma += s.size
                if runs_here or stored_here:
                    tag = s.name
                    if s.lma != s.addr and stored_here and not runs_here:
                        tag += " (load image)"
                    names.append(tag)
            uses.append(RegionUse(r, vma, lma, names))
        return uses

    # -- layout --------------------------------------------------------------

    def layout(self) -> str:
        e = self.elf
        entry_sym = e.symbol_at(e.entry)
        out = [f"{os.path.basename(e.path)}: {e.machine}, {e.bits}-bit, entry {e.entry:#x}"
               + (f" <{entry_sym.name}>" if entry_sym else "")]
        out.append("")
        out.append("Segments (what the loader maps):")
        for seg in e.segments:
            if not seg.loadable:
                continue
            lma_note = "" if seg.paddr == seg.vaddr else f"  LMA {seg.paddr:#x}"
            out.append(f"  [{seg.index}] LOAD {seg.flags}  VMA {seg.vaddr:#x}{lma_note}  "
                       f"file {seg.filesz:#x} / mem {seg.memsz:#x} bytes  (file offset {seg.offset:#x})")
            for s in e.alloc_sections:
                if seg.vaddr <= s.addr < seg.vaddr + max(seg.memsz, 1):
                    out.append(f"        {s.name:<22} {s.addr:#010x}+{s.size:#x}  {s.kind}")
        unmapped = [s for s in e.alloc_sections if e.segment_of(s) is None]
        if unmapped:
            out.append("  Allocated sections in no LOAD segment (won't be loaded!): "
                       + ", ".join(s.name for s in unmapped))
        gaps = self._gaps()
        if gaps:
            out.append("")
            out.append("Gaps between sections (alignment padding or `. =` jumps):")
            for a, b, size in gaps:
                out.append(f"  {a} -> {b}: {size:#x} ({size}) bytes")
        uses = self.region_usage()
        if uses:
            out.append("")
            out.append("Memory regions:")
            for u in uses:
                pct = 100 * u.used / u.region.length if u.region.length else 0
                flag = "  <-- NEARLY FULL" if pct >= NEARLY_FULL * 100 else ""
                out.append(f"  {u.region.name:<8} {u.region.origin:#010x}  {_kib(u.used)} of "
                           f"{_kib(u.region.length)} used ({pct:.1f}%){flag}")
                out.append(f"           {', '.join(u.sections) or '(empty)'}")
        elif self.script is None and (self.map is None or not self.map.regions):
            out.append("")
            out.append("(No MEMORY regions known: pass the linker script, or a GNU ld map, to "
                       "see region usage.)")
        return "\n".join(out)

    def _gaps(self) -> list[tuple[str, str, int]]:
        secs = self.elf.alloc_sections
        out = []
        for a, b in zip(secs, secs[1:]):
            end = a.addr + a.size
            if b.addr > end and b.addr - end < 0x100000 and self.region_of(a.addr) == self.region_of(b.addr):
                out.append((a.name, b.name, b.addr - end))
        return out

    # -- where -----------------------------------------------------------------

    def resolve(self, query: str) -> tuple[int, str]:
        q = query.strip()
        try:
            return int(q, 0), f"{int(q, 0):#x}"
        except ValueError:
            pass
        m = re.match(r"^([A-Za-z_.$][\w.$]*)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)$", q)
        base, off = (m.group(1), int(m.group(3), 0) * (1 if m.group(2) == "+" else -1)) if m else (q, 0)
        sym = self.elf.symbol(base)
        if sym is not None:
            return sym.address + off, q
        if self.map is not None:
            hit = self.map.symbol(base)
            if hit is not None:
                return hit[2].address + off, q
        sec = next((s for s in self.elf.alloc_sections if s.name == base), None)
        if sec is not None:
            return sec.addr + off, q
        similar = self.elf.similar(base)
        hint = f" Similar: {', '.join(similar)}." if similar else ""
        raise LinkError(f"no symbol or section named {base!r} in {os.path.basename(self.elf.path)}.{hint}")

    def where(self, query: str) -> str:
        address, label = self.resolve(query)
        e = self.elf
        lines: list[str] = []
        sym = e.symbol(label.split("+")[0].split("-")[0].strip()) if not label.startswith("0x") else None
        if sym is None:
            # An address in a load image names the variable it will become.
            img = e.section_at_lma(address) if e.section_at(address) is None else None
            sym = e.symbol_at(img.addr + (address - img.lma) if img else address)
        head = "" if label.startswith("0x") else label
        if sym is not None:
            size = f", {sym.size} bytes" if sym.size else ""
            thumb = ", Thumb" if sym.thumb else ""
            head += f" = {sym.name} ({sym.type}{size}{thumb})" if head else f"{sym.name} ({sym.type}{size}{thumb})"
        head = f"{head} at {address:#x}" if head else f"{address:#x}"
        lines.append(head)

        sec = e.section_at(address)
        load_image_of = None if sec else e.section_at_lma(address)
        if sec is None and load_image_of is None:
            region = self.region_of(address)
            lines.append("  Not inside any allocated section"
                         + (f" (it is in region {region.name})." if region else ".")
                         + " It may be a linker-defined symbol marking a boundary, or memory "
                         "the image doesn't describe.")
            return "\n".join(lines)
        if load_image_of is not None:
            s = load_image_of
            lines.append(f"  This is the LOAD IMAGE of {s.name}: bytes stored at LMA {s.lma:#x} "
                         f"that startup code copies to VMA {s.addr:#x} before {s.name} is used.")
            sec = s
            address = s.addr + (address - s.lma)

        assert sec is not None
        step = 1
        # 1. Input section and object file (map file)
        if self.map is not None:
            hit = self.map.input_at(address)
            if hit is not None:
                out, inp = hit
                lines.append(f"  {step}. came from input section {inp.name} in {inp.file} "
                             f"({inp.vma:#x}+{inp.size:#x})")
                step += 1
                rule = self._rule_for(out, inp)
                if rule:
                    lines.append(f"  {step}. {rule}")
                    step += 1
        else:
            lines.append("  (pass map= to see which object file and input section it came from)")

        # 2. Output section and segment
        seg = e.segment_of(sec)
        seg_txt = f", in LOAD segment [{seg.index}] {seg.flags}" if seg else ", in NO loadable segment"
        lines.append(f"  {step}. {_lead(step)} part of output section {sec.name} "
                     f"({sec.addr:#x}-{sec.addr + sec.size - 1:#x}, {sec.kind}){seg_txt}")
        step += 1

        # 3. Region, and why
        vregion = self.region_of(sec.addr)
        lregion = self.region_of(sec.lma)
        stmt = self.script.output(sec.name) if self.script else None
        if vregion is not None:
            why = ""
            if stmt is not None and stmt.region:
                why = f" because the script says `{sec.name} : {{...}} > {stmt.region}` (line {stmt.line})"
            elif stmt is None and self.script is not None:
                why = (" - the script doesn't name this section, so it is an ORPHAN that the "
                       "linker placed by its own heuristics")
            lines.append(f"  {step}. {_lead(step, 'runs')} in region {vregion.name} "
                         f"({vregion.origin:#x}+{vregion.length:#x}){why}")
            step += 1
        elif self.regions:
            lines.append(f"  {step}. {_lead(step)} OUTSIDE every MEMORY region")
            step += 1
        elif stmt is not None and self.script is not None:
            lines.append(f"  {step}. placed by `{sec.name}` in the script (line {stmt.line}); "
                         f"no MEMORY regions, so the location counter decides the address")
            step += 1
        if sec.lma != sec.addr:
            via = ""
            if stmt is not None and stmt.lma_region:
                via = f" (`AT> {stmt.lma_region}`, line {stmt.line})"
            elif stmt is not None and stmt.at:
                via = f" (`AT({stmt.at})`, line {stmt.line})"
            where_l = f" in {lregion.name}" if lregion else ""
            if sec.nobits:
                lines.append(f"  {step}. its LMA ({sec.lma:#x}) differs, but it is NOBITS: nothing is "
                             "stored, startup code zero-fills it")
            else:
                lines.append(f"  {step}. and is stored at LMA {sec.lma:#x}{where_l}{via}: "
                             f"copy {sec.size:#x} bytes from {sec.lma:#x} to {sec.addr:#x} at boot")
            step += 1
        if sym is not None and sym.size and address != sym.address:
            lines.append(f"  (address is {address - sym.address:#x} bytes into {sym.name})")
        return "\n".join(lines)

    def _rule_for(self, out: OutputSection, inp: InputSection) -> str | None:
        if inp.pattern:
            return f"which the script rule `{inp.pattern}` sent to {out.name} (from the GNU map)"
        if self.script is None:
            return None
        hit = self.script.rule_for(inp.file, inp.name)
        if hit is None:
            return (f"which no rule in the script matches - {inp.name} is an ORPHAN section "
                    f"that the linker put in {out.name} on its own")
        stmt, rule = hit
        if stmt.name != out.name:
            return (f"which the script rule `{rule.text}` (line {stmt.line}) should send to "
                    f"{stmt.name}, but it ended up in {out.name} - the map and script disagree")
        keep = " (KEEP: survives --gc-sections)" if rule.keep else ""
        return f"which the script rule `{rule.text}` in {stmt.name} (line {stmt.line}) captured{keep}"

    # -- overlaps / problems ---------------------------------------------------

    def problems(self) -> str:
        e = self.elf
        out: list[str] = []
        secs = e.alloc_sections
        for i, a in enumerate(secs):
            for b in secs[i + 1:]:
                if a.addr < b.addr + b.size and b.addr < a.addr + a.size:
                    out.append(f"OVERLAP (VMA): {a.name} {a.addr:#x}+{a.size:#x} and {b.name} "
                               f"{b.addr:#x}+{b.size:#x} share {self._overlap(a.addr, a.size, b.addr, b.size):#x} bytes")
        stored = [s for s in secs if not s.nobits]
        for i, a in enumerate(stored):
            for b in stored[i + 1:]:
                if (a.lma, b.lma) != (a.addr, b.addr) and a.lma < b.lma + b.size and b.lma < a.lma + a.size:
                    out.append(f"OVERLAP (LMA): the stored bytes of {a.name} and {b.name} overlap "
                               f"at {max(a.lma, b.lma):#x} - one will overwrite the other in the image")
        loads = [s for s in e.segments if s.loadable and s.memsz]
        for i, sa in enumerate(loads):
            for sb in loads[i + 1:]:
                if sa.vaddr < sb.vaddr + sb.memsz and sb.vaddr < sa.vaddr + sa.memsz:
                    out.append(f"OVERLAP (segments): LOAD [{sa.index}] and [{sb.index}] overlap in memory")
        for seg in loads:
            if "W" in seg.flags and "X" in seg.flags:
                inside = [s.name for s in secs if seg.vaddr <= s.addr < seg.vaddr + seg.memsz]
                out.append(f"RWX SEGMENT: LOAD [{seg.index}] is writable AND executable "
                           f"({', '.join(inside)}). Code and writable data share pages, so a stray "
                           "write can corrupt code. Usually caused by a section with no region or "
                           "segment of its own; GNU ld also warns about this.")
        for s in secs:
            # NOBITS sections can get an LMA just by sharing a segment with
            # .data (GNU ld); there are no bytes to copy, so that's not news.
            if s.lma != s.addr and not s.nobits:
                out.append(f"COPY NEEDED: {s.name} runs at {s.addr:#x} but is stored at {s.lma:#x}. "
                           f"Startup must copy {s.size:#x} ({s.size}) bytes: "
                           f"memcpy({s.addr:#x}, {s.lma:#x}, {s.size:#x}).")
        if self.regions:
            for s in secs:
                if self.region_of(s.addr) is None:
                    out.append(f"OUTSIDE REGIONS: {s.name} at {s.addr:#x} is in no MEMORY region")
                elif self.region_of(s.addr + s.size - 1) != self.region_of(s.addr):
                    out.append(f"CROSSES REGION END: {s.name} {s.addr:#x}+{s.size:#x} runs past "
                               f"the end of {self.region_of(s.addr).name}")  # type: ignore[union-attr]
            for u in self.region_usage():
                frac = u.used / u.region.length if u.region.length else 0
                if frac > 1:
                    out.append(f"OVERFLOW: {u.region.name} needs {_kib(u.used)} but has {_kib(u.region.length)}")
                elif frac >= NEARLY_FULL:
                    out.append(f"NEARLY FULL: {u.region.name} is {100 * frac:.1f}% used "
                               f"({_kib(u.region.length - u.used)} free). Biggest users: "
                               + self._top_in_region(u.region))
        if self.script is not None:
            named = {o.name for o in self.script.outputs}
            orphans = [s.name for s in secs if s.name not in named]
            if orphans:
                out.append("ORPHANS: " + ", ".join(orphans) + " - not named in the linker script; the "
                           "linker placed them by heuristic. Name them (or /DISCARD/ them) so their "
                           "placement is intentional.")
        if self.map is not None and self.map.discarded:
            kept = [f"{d.name} ({d.file}, {d.size:#x})" for d in self.map.discarded if d.size]
            if kept:
                out.append("DISCARDED: " + ", ".join(kept[:12]) + (" ..." if len(kept) > 12 else ""))
        return "\n".join(out) if out else "No overlaps, overflows, orphans or copy requirements found."

    @staticmethod
    def _overlap(a: int, an: int, b: int, bn: int) -> int:
        return min(a + an, b + bn) - max(a, b)

    def _top_in_region(self, region: Region) -> str:
        items = [(s.size, s.name) for s in self.elf.symbols
                 if s.size and region.contains(s.address)]
        for s in self.elf.alloc_sections:
            if s.lma != s.addr and not s.nobits and region.contains(s.lma):
                items.append((s.size, f"{s.name} load image"))
        items.sort(reverse=True)
        return ", ".join(f"{n} ({_kib(sz)})" for sz, n in items[:3]) or "(no sized symbols)"

    # -- biggest ---------------------------------------------------------------

    def biggest(self, by: str, limit: int, region: str | None) -> str:
        reg = None
        if region is not None:
            reg = next((r for r in self.regions if r.name.lower() == region.lower()), None)
            if reg is None:
                known = ", ".join(r.name for r in self.regions) or "none known"
                raise LinkError(f"no MEMORY region {region!r} (regions: {known})")

        def in_region(vma: int, lma: int, nobits: bool) -> bool:
            if reg is None:
                return True
            return reg.contains(vma) or (not nobits and reg.contains(lma))

        rows: list[tuple[int, str]] = []
        if by == "symbol":
            for s in self.elf.symbols:
                sec = self.elf.section_at(s.address)
                if s.size and sec and in_region(s.address, sec.lma + (s.address - sec.addr), sec.nobits):
                    rows.append((s.size, f"{s.name} ({s.type}, {sec.name})"))
        elif by in ("input", "object"):
            if self.map is None:
                raise LinkError(f"by={by!r} needs a map file - call link_load with map=")
            agg: dict[str, int] = {}
            for out, inp in self.map.inputs():
                sec = next((s for s in self.elf.alloc_sections if s.name == out.name), None)
                if sec is None or not inp.size:
                    continue
                if not in_region(inp.vma, inp.lma, sec.nobits):
                    continue
                key = f"{inp.name} ({inp.file})" if by == "input" else inp.file
                agg[key] = agg.get(key, 0) + inp.size
            rows = [(v, k) for k, v in agg.items()]
        elif by == "section":
            for osec in self.elf.alloc_sections:
                if in_region(osec.addr, osec.lma, osec.nobits):
                    rows.append((osec.size, f"{osec.name} ({osec.kind})"))
        else:
            raise LinkError('by must be "symbol", "input", "object" or "section"')
        rows.sort(reverse=True)
        total = sum(r[0] for r in rows)
        scope = f" in {reg.name}" if reg else ""
        lines = [f"Largest {by}s{scope} ({len(rows)} total, {_kib(total)}):"]
        for size, name in rows[:limit]:
            pct = 100 * size / total if total else 0
            lines.append(f"  {size:>8}  {pct:5.1f}%  {name}")
        return "\n".join(lines)

    # -- diff --------------------------------------------------------------------

    def diff(self, other: Linked) -> str:
        lines = [f"{self.name} -> {other.name}:"]
        a = {s.name: s for s in self.elf.alloc_sections}
        b = {s.name: s for s in other.elf.alloc_sections}
        sec_rows = []
        for name in sorted(set(a) | set(b)):
            sa = a[name].size if name in a else 0
            sb = b[name].size if name in b else 0
            if sa != sb:
                sec_rows.append(f"  {name:<22} {sa:>8} -> {sb:>8}  ({sb - sa:+d})")
        lines.append("Sections:" if sec_rows else "Sections: no size changes")
        lines += sec_rows
        ua = {u.region.name: u for u in self.region_usage()}
        ub = {u.region.name: u for u in other.region_usage()}
        reg_rows = []
        for name in ua.keys() & ub.keys():
            x, y = ua[name].used, ub[name].used
            if x != y:
                length = ub[name].region.length
                reg_rows.append(f"  {name:<8} {x:>8} -> {y:>8}  ({y - x:+d}), now "
                                f"{100 * y / length:.1f}% full")
        if reg_rows:
            lines.append("Regions:")
            lines += sorted(reg_rows)
        sa_ = {s.name: s.size for s in self.elf.symbols if s.size}
        sb_ = {s.name: s.size for s in other.elf.symbols if s.size}
        added = sorted(((sb_[n], n) for n in sb_.keys() - sa_.keys()), reverse=True)
        removed = sorted(((sa_[n], n) for n in sa_.keys() - sb_.keys()), reverse=True)
        changed = sorted(((sb_[n] - sa_[n], n) for n in sa_.keys() & sb_.keys() if sb_[n] != sa_[n]),
                         key=lambda t: -abs(t[0]))
        if added:
            lines.append("New symbols: " + ", ".join(f"{n} (+{s})" for s, n in added[:15]))
        if removed:
            lines.append("Removed symbols: " + ", ".join(f"{n} (-{s})" for s, n in removed[:15]))
        if changed:
            lines.append("Resized symbols: " + ", ".join(f"{n} ({d:+d})" for d, n in changed[:15]))
        if len(lines) == 2 and not sec_rows:
            lines.append("No differences in sections or sized symbols.")
        return "\n".join(lines)


def _lead(step: int, verb: str = "is") -> str:
    """Steps after the first continue a sentence ("which is ..."); the first starts one."""
    return f"which {verb}" if step > 1 else f"it {verb}"


def _kib(n: int) -> str:
    if n >= 1024:
        return f"{n / 1024:.2f} KiB"
    return f"{n} B"


def section_names(secs: list[Section]) -> str:
    return ", ".join(s.name for s in secs)
