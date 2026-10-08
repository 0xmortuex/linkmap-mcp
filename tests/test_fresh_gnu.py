"""Check the parser against maps GNU ld produced moments ago in CI.

The committed GNU fixtures came from GNU ld 2.44; this runs against whatever
GNU ld the CI image ships, so a format change shows up as a failure.
Set LINKMAP_FRESH_GNU to the output directory of tests/fixtures/build_gnu.sh.
"""

import os

import pytest

from conftest import fx
from linkmap_mcp.analysis import Linked

FRESH = os.environ.get("LINKMAP_FRESH_GNU")
pytestmark = pytest.mark.skipif(not FRESH, reason="set LINKMAP_FRESH_GNU (see build_gnu.sh)")


def _linked(stem: str, script: str) -> Linked:
    assert FRESH is not None
    return Linked(stem, os.path.join(FRESH, stem + ".elf"), os.path.join(FRESH, stem + ".map"), script)


@pytest.mark.parametrize("stem,script", [
    ("kernel-gnu", fx("x86", "linker.ld")),
    ("firmware-gnu", fx("embedded", "link.ld")),
])
def test_map_symbols_match_the_elf(stem, script):
    L = _linked(stem, script)
    assert L.map is not None and L.map.format == "gnu"
    checked = 0
    for _, inp in L.map.inputs():
        for s in inp.symbols:
            elf_sym = L.elf.symbol(s.name)
            if elf_sym is not None:
                assert elf_sym.address == s.address, s.name
                checked += 1
    assert checked >= 4


def test_fresh_embedded_chain():
    L = _linked("firmware-gnu", fx("embedded", "link.ld"))
    assert [r.name for r in L.map.regions] == ["FLASH", "RAM"]
    text = L.where("boot_count")
    # Objects linked by absolute path keep it in the map (/tmp/.../main.o).
    assert "input section .data.boot_count in " in text and "main.o (0x20000000+0x4)" in text
    assert "AT> FLASH" in text and "copy 0x24 bytes" in text
