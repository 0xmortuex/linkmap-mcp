"""Map parsing against real GNU ld 2.44 and lld (zig 0.16) output."""

import pytest

from conftest import fx
from linkmap_mcp import mapfile


def _input(m, name):
    return next(i for _, i in m.inputs() if i.name == name)


def test_format_detection():
    assert mapfile.parse(fx("x86", "kernel-lld.map")).format == "lld"
    assert mapfile.parse(fx("x86", "kernel-gnu.map")).format == "gnu"


def test_unknown_format_is_explained(tmp_path):
    p = tmp_path / "x.map"
    p.write_text("Archive member included to satisfy reference by file (symbol)\n", encoding="utf-8")
    with pytest.raises(ValueError, match="-Wl,-Map=out.map"):
        mapfile.parse(str(p))
    with pytest.raises(FileNotFoundError):
        mapfile.parse(str(tmp_path / "missing.map"))


@pytest.mark.parametrize("name", ["kernel-lld.map", "kernel-gnu.map"])
def test_x86_inputs_and_symbols(name):
    m = mapfile.parse(fx("x86", name))
    text = next(o for o in m.sections if o.name == ".text")
    names = [i.name for i in text.inputs]
    assert names[0] == ".multiboot" and ".text.kmain" in names
    kmain = _input(m, ".text.kmain")
    assert kmain.file == "kernel.o" and kmain.size > 0
    assert [s.name for s in kmain.symbols] == ["kmain"]
    assert kmain.symbols[0].address == kmain.vma
    out, inp, sym = m.symbol("counter")
    assert out.name == ".bss" and inp.name == ".bss.counter"


def test_gnu_wrapped_names_patterns_and_regions():
    m = mapfile.parse(fx("x86", "kernel-gnu.map"))
    # ".text.triple_fault" is too long for its column, so GNU wraps it.
    tf = _input(m, ".text.triple_fault")
    assert tf.size == 0xF and tf.file == "kernel.o" and tf.pattern == "*(.text*)"
    assert _input(m, ".multiboot").pattern == "*(.multiboot)"
    assert m.regions == []  # only *default*, which is skipped


def test_gnu_embedded_memory_load_address_fill_and_discards():
    m = mapfile.parse(fx("embedded", "firmware-gnu.map"))
    assert [(r.name, r.origin, r.length, r.attributes) for r in m.regions] == [
        ("FLASH", 0x08000000, 0x4000, "xr"), ("RAM", 0x20000000, 0x1000, "xrw")]
    data = next(o for o in m.sections if o.name == ".data")
    assert (data.vma, data.lma, data.size) == (0x20000000, 0x08003870, 0x24)
    # Input LMAs follow the output section's load address.
    assert _input(m, ".data.device_name").lma == 0x08003874
    text = next(o for o in m.sections if o.name == ".text")
    assert text.fill == 4  # two 2-byte *fill* runs between functions
    assert any(d.name == ".ARM.exidx.text.main" and d.file == "main.o" for d in m.discarded)
    assert ("_etext = ." in [a for _, a in text.assignments])


def test_lld_embedded_lma_and_thumb_bit_kept_raw():
    m = mapfile.parse(fx("embedded", "firmware-lld.map"))
    data = next(o for o in m.sections if o.name == ".data")
    assert (data.vma, data.lma) == (0x20000000, 0x08003870)
    main_sym = m.symbol("main")[2]
    assert main_sym.address & 1  # lld prints Thumb functions with bit 0 set
    assert not any(s.name.startswith("$") for _, i in m.inputs() for s in i.symbols)
    assert ("_stack_size = 0x400" in [a for _, a in m.top_assignments])


def test_input_at_picks_the_covering_input():
    m = mapfile.parse(fx("embedded", "firmware-lld.map"))
    out, inp = m.input_at(0x20000005)
    assert out.name == ".data" and inp.name == ".data.device_name"
    assert m.input_at(0x30000000) is None
