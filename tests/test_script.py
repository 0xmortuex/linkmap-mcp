import pytest

from conftest import fx
from linkmap_mcp import script as S


def test_embedded_script_structure():
    ls = S.parse(fx("embedded", "link.ld"))
    assert ls.entry == "reset_handler"
    assert [(r.name, r.origin, r.length, r.attributes) for r in ls.regions] == [
        ("FLASH", 0x08000000, 16 * 1024, "rx"), ("RAM", 0x20000000, 4 * 1024, "rwx")]
    data = ls.output(".data")
    assert (data.region, data.lma_region, data.line) == ("RAM", "FLASH", 32)
    assert ls.output(".bss").type == "NOLOAD"
    vec = ls.output(".isr_vector")
    assert vec.rules[0].keep and vec.rules[0].section_patterns == [".isr_vector"]
    assert [r.text for r in ls.output(".text").rules] == ["*(.text*)", "*(.rodata*)"]
    assert [r.text for r in ls.output("/DISCARD/").rules] == ["*(.ARM.exidx*)", "*(.comment)"]


def test_first_matching_rule_wins_including_discard():
    ls = S.parse(fx("embedded", "link.ld"))
    assert ls.rule_for("main.o", ".rodata.font_bitmap")[0].name == ".text"
    assert ls.rule_for("startup.o", ".ARM.exidx.text.reset_handler")[0].name == "/DISCARD/"
    assert ls.rule_for("main.o", ".ARM.extab.text.main") is None  # an orphan


def test_explicit_address_at_and_exclude_file():
    ls = S.parse_text("""
        /* comment with SECTIONS { inside } */
        MEMORY { rom (rx) : ORG = 0x0, LEN = 64K - 0x200
                 ram (!rx) : o = 1M, l = 0x8000 }
        SECTIONS {
          . = 0x100000;
          .boot 0x7c00 : AT(0x1000) ALIGN(16) { KEEP(*crt0.o(.boot .boot.*)) }
          .ctors : { *(EXCLUDE_FILE(*crtend.o) .ctors) SORT(*)(.init_array) }
          PROVIDE(__end = .);
        }""")
    assert [(r.name, r.origin, r.length) for r in ls.regions] == [
        ("rom", 0, 64 * 1024 - 0x200), ("ram", 1024 * 1024, 0x8000)]
    boot = ls.output(".boot")
    assert (boot.address, boot.at, boot.align) == ("0x7c00", "0x1000", "16")
    rule = boot.rules[0]
    assert rule.keep and rule.file_pattern == "*crt0.o" and rule.section_patterns == [".boot", ".boot.*"]
    assert rule.matches("build/crt0.o", ".boot.text") and not rule.matches("main.o", ".boot")
    ctors = ls.output(".ctors").rules[0]
    assert ctors.excluded_files == ["*crtend.o"]
    assert ctors.matches("crtbegin.o", ".ctors") and not ctors.matches("crtend.o", ".ctors")
    assert (16, "PROVIDE(__end = .)") not in ls.top_statements
    assert any("PROVIDE(__end = .)" == s for _, s in ls.top_statements)


def test_archive_member_patterns():
    r = S._parse_rule("*libc.a:*(.text .text.*)")
    assert r.matches("/usr/lib/libc.a(memcpy.o)", ".text.memcpy")
    assert not r.matches("main.o", ".text")


@pytest.mark.parametrize("expr,value", [("0x8000000", 0x8000000), ("16K", 16384), ("1M", 1 << 20),
                                        ("64K - 0x200", 65024), ("4 * 1024", 4096)])
def test_eval_number(expr, value):
    assert S.eval_number(expr) == value


def test_eval_number_rejects_symbols():
    with pytest.raises(ValueError, match="only constants"):
        S.eval_number("__flash_size")


def test_explain_mentions_the_important_parts():
    text = S.explain(S.parse(fx("embedded", "link.ld")))
    assert "Execution starts at `reset_handler`" in text
    assert "FLASH: 0x8000000-0x8003fff, 16 KiB (read, execute)" in text
    assert "stored in FLASH (LMA) - startup code must copy it from FLASH to RAM" in text
    assert "KEEP: kept even if nothing references it" in text
    assert "reserves _stack_size bytes" in text
    assert "/DISCARD/ (line 58)" in text and "*(.comment)" in text
    assert "defines _estack only if the program doesn't define it itself" in text


def test_no_memory_explained():
    text = S.explain(S.parse(fx("x86", "linker.ld")))
    assert "No MEMORY command" in text and "`. = 1M` moves the location counter" in text


def test_missing_script():
    with pytest.raises(FileNotFoundError):
        S.parse("nope.ld")
