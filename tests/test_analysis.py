"""The explanations, against real binaries from both linkers."""

import pytest

from conftest import fx
from linkmap_mcp.analysis import Linked, LinkError


def emb(kind: str, version: str = "") -> Linked:
    base = f"firmware-{kind}{version}"
    return Linked(base, fx("embedded", base + ".elf"), fx("embedded", base + ".map"),
                  fx("embedded", "link.ld"))


@pytest.mark.parametrize("kind", ["lld", "gnu"])
def test_where_walks_the_whole_chain_for_data(kind):
    text = emb(kind).where("boot_count")
    assert "boot_count (object, 4 bytes) at 0x20000000" in text
    assert "input section .data.boot_count in main.o" in text
    assert "`*(.data*)`" in text
    assert "output section .data" in text
    assert "runs in region RAM" in text and "`.data : {...} > RAM` (line 32)" in text
    assert "stored at LMA 0x8003870 in FLASH (`AT> FLASH`, line 32)" in text
    assert "copy 0x24 bytes from 0x8003870 to 0x20000000" in text


@pytest.mark.parametrize("kind", ["lld", "gnu"])
def test_thumb_function_resolves_to_its_real_address(kind):
    text = emb(kind).where("main")
    assert "main (func, 228 bytes, Thumb) at 0x80000d0" in text
    assert "input section .text.main in main.o" in text


def test_address_in_a_load_image_names_the_variable():
    text = emb("gnu").where("0x8003874")
    assert text.startswith("device_name (object, 32 bytes) at 0x8003874")
    assert "LOAD IMAGE of .data" in text


def test_where_offset_and_unknown_symbol():
    assert "(address is 0x10 bytes into font_bitmap)" in emb("lld").where("font_bitmap+0x10")
    with pytest.raises(LinkError, match="Similar: boot_count"):
        emb("lld").where("boot")


def test_orphan_section_is_called_out_in_where():
    text = emb("lld").where(".ARM.extab.text.main")
    assert "no rule in the script matches" in text and "ORPHAN" in text


def test_without_map_or_script_it_still_answers():
    lone = Linked("lone", fx("embedded", "firmware-lld.elf"))
    text = lone.where("boot_count")
    assert "pass map=" in text and "output section .data" in text
    assert "No MEMORY regions known" in lone.layout()


def test_region_usage_counts_load_images_in_flash():
    use = {u.region.name: u for u in emb("lld").region_usage()}
    assert ".data (load image)" in use["FLASH"].sections
    assert use["FLASH"].used == 0x40 + 0x3824 + 0xC + 0x24
    assert use["RAM"].vma_bytes == 0x24 + 0x400 + 0x404


def test_problems_copy_loop_orphans_and_discards():
    text = emb("gnu").problems()
    assert "memcpy(0x20000000, 0x8003870, 0x24)" in text
    assert "ORPHANS: .ARM.extab.text.main" in text
    assert "DISCARDED: .ARM.exidx.text.reset_handler" in text
    assert "RWX SEGMENT: LOAD [0]" in text
    # NOBITS sections that merely share .data's segment need no copy.
    assert ".bss runs at" not in text and "ZERO-FILL" not in text


def test_nearly_full_region_names_the_culprits():
    text = emb("lld", "-v2").problems()
    assert "NEARLY FULL: FLASH is 92.7% used" in text
    assert "font_bitmap (13.67 KiB)" in text


def test_overlaps_are_found():
    o = Linked("o", fx("overlap", "overlap.elf"), fx("overlap", "overlap.map"), fx("overlap", "overlap.ld"))
    text = o.problems()
    assert "OVERLAP (VMA): .text 0x1000+0x5d and .rodata 0x1010+0xc share 0xc bytes" in text
    assert "OVERLAP (segments)" in text


def test_biggest():
    L = emb("lld")
    assert L.biggest("symbol", 1, None).splitlines()[1].endswith("font_bitmap (object, .text)")
    by_obj = L.biggest("object", 5, "FLASH")
    assert "main.o" in by_obj.splitlines()[1]
    assert "Largest inputs in RAM" in L.biggest("input", 3, "ram")
    with pytest.raises(LinkError, match="regions: FLASH, RAM"):
        L.biggest("symbol", 5, "SRAM")
    with pytest.raises(LinkError, match="needs a map file"):
        Linked("lone", fx("embedded", "firmware-lld.elf")).biggest("object", 5, None)
    with pytest.raises(LinkError, match='by must be'):
        L.biggest("file", 5, None)


def test_diff_between_builds():
    text = emb("lld").diff(emb("lld", "-v2"))
    assert ".text                     14372 ->    15076  (+704)" in text
    assert "FLASH       14484 ->    15188  (+704), now 92.7% full" in text
    assert "New symbols: log_banner (+600), log_ring (+256)" in text
    assert "main (+102)" in text


@pytest.mark.parametrize("kind", ["lld", "gnu"])
def test_x86_kernel(kind):
    L = Linked(kind, fx("x86", f"kernel-{kind}.elf"), fx("x86", f"kernel-{kind}.map"), fx("x86", "linker.ld"))
    text = L.where("kmain")
    assert "input section .text.kmain in kernel.o" in text
    assert "no MEMORY regions, so the location counter decides the address" in text
    assert "ORPHANS: .eh_frame" in L.problems()


def test_map_and_elf_agree_on_every_symbol():
    """Every symbol the map places must be where the ELF says it is."""
    for kind in ("lld", "gnu"):
        L = emb(kind)
        assert L.map is not None
        for _, inp in L.map.inputs():
            for s in inp.symbols:
                elf_sym = L.elf.symbol(s.name)
                if elf_sym is not None:
                    assert elf_sym.address == s.address, (kind, s.name)
