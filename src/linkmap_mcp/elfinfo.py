"""What the ELF itself says: segments, sections and symbols (via pyelftools).

The ELF is the ground truth for where things ARE. The map file and linker
script (see mapfile.py, script.py) explain WHY they are there.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


@dataclass(frozen=True)
class Segment:
    index: int
    type: str  # PT_LOAD, PT_GNU_STACK...
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: str  # "R-X"

    @property
    def loadable(self) -> bool:
        return self.type == "PT_LOAD"


@dataclass(frozen=True)
class Section:
    name: str
    addr: int  # VMA
    lma: int  # load address, derived from the segment that contains it
    size: int
    type: str  # SHT_PROGBITS, SHT_NOBITS...
    flags: int
    offset: int

    @property
    def alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    @property
    def nobits(self) -> bool:
        return self.type == "SHT_NOBITS"

    @property
    def kind(self) -> str:
        if not self.alloc:
            return "not loaded"
        if self.flags & SHF_EXECINSTR:
            return "code"
        if self.nobits:
            return "zero-initialised (no file bytes)"
        if self.flags & SHF_WRITE:
            return "initialised data"
        return "read-only data"


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int  # Thumb bit already removed
    size: int
    type: str  # "func" | "object" | "other"
    section: str | None
    thumb: bool = False


class ElfImage:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"ELF not found: {path}")
        with open(self.path, "rb") as fh:
            try:
                elf = ELFFile(fh)
            except Exception as e:  # pyelftools raises its own ELFError on garbage
                raise ValueError(f"{path} is not a valid ELF file: {e}") from None
            self.machine = elf.get_machine_arch()
            self.bits = elf.elfclass
            self.entry = elf.header["e_entry"]
            self.segments = [
                Segment(
                    i, seg["p_type"], seg["p_offset"], seg["p_vaddr"], seg["p_paddr"],
                    seg["p_filesz"], seg["p_memsz"], _flags(seg["p_flags"]),
                )
                for i, seg in enumerate(elf.iter_segments())
            ]
            raw_sections = [s for s in elf.iter_sections() if s.name]
            self.sections = [
                Section(
                    s.name, s["sh_addr"], self._lma_of(s["sh_addr"], s["sh_flags"]),
                    s["sh_size"], s["sh_type"], s["sh_flags"], s["sh_offset"],
                )
                for s in raw_sections
            ]
            names = {i: s.name for i, s in enumerate(elf.iter_sections())}
            self.symbols = self._load_symbols(elf, names)
        self.entry &= ~1 if self.machine == "ARM" else ~0

    def _lma_of(self, vma: int, flags: int) -> int:
        """A section's LMA is where its segment loads it: paddr + (vma - vaddr)."""
        if not flags & SHF_ALLOC:
            return vma
        for seg in self.segments:
            if seg.loadable and seg.vaddr <= vma < seg.vaddr + max(seg.memsz, 1):
                return seg.paddr + (vma - seg.vaddr)
        return vma

    def _load_symbols(self, elf: ELFFile, names: dict[int, str]) -> list[Symbol]:
        out: list[Symbol] = []
        sec = elf.get_section_by_name(".symtab")
        if sec is None or not hasattr(sec, "iter_symbols"):
            return out
        arm = self.machine == "ARM"
        for sym in sec.iter_symbols():
            stype = sym["st_info"]["type"]
            name = sym.name
            # $t/$d/$a are ARM mapping symbols, not program symbols.
            if not name or stype in ("STT_SECTION", "STT_FILE") or name.startswith("$"):
                continue
            if sym["st_shndx"] in ("SHN_UNDEF", "SHN_ABS"):
                continue
            value = sym["st_value"]
            thumb = arm and stype == "STT_FUNC" and bool(value & 1)
            if thumb:
                value &= ~1
            kind = {"STT_FUNC": "func", "STT_OBJECT": "object"}.get(stype, "other")
            shndx = sym["st_shndx"]
            out.append(Symbol(name, value, sym["st_size"], kind,
                              names.get(shndx) if isinstance(shndx, int) else None, thumb))
        return out

    # -- queries -------------------------------------------------------------

    @property
    def alloc_sections(self) -> list[Section]:
        return sorted((s for s in self.sections if s.alloc and s.size), key=lambda s: s.addr)

    def symbol(self, name: str) -> Symbol | None:
        for s in self.symbols:
            if s.name == name:
                return s
        return None

    def similar(self, name: str, limit: int = 8) -> list[str]:
        low = name.lower()
        return sorted({s.name for s in self.symbols if low in s.name.lower()})[:limit]

    def section_at(self, address: int) -> Section | None:
        """The allocated section whose VMA range holds address."""
        for s in self.alloc_sections:
            if s.addr <= address < s.addr + s.size:
                return s
        return None

    def section_at_lma(self, address: int) -> Section | None:
        """A section whose LOAD image (LMA != VMA) holds address."""
        for s in self.alloc_sections:
            if s.lma != s.addr and not s.nobits and s.lma <= address < s.lma + s.size:
                return s
        return None

    def symbol_at(self, address: int) -> Symbol | None:
        best: Symbol | None = None
        for s in self.symbols:
            if s.address <= address and (address < s.address + s.size or (
                    s.size == 0 and s.address == address)):
                if best is None or s.size < best.size or (best.type == "other" and s.type != "other"):
                    best = s
        return best

    def segment_of(self, section: Section) -> Segment | None:
        for seg in self.segments:
            if seg.loadable and seg.vaddr <= section.addr < seg.vaddr + max(seg.memsz, 1):
                return seg
        return None


def _flags(p_flags: int) -> str:
    return ("R" if p_flags & 4 else "-") + ("W" if p_flags & 2 else "-") + ("X" if p_flags & 1 else "-")
