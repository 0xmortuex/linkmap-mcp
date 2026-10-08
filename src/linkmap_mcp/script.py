"""A practical parser for GNU ld / lld linker scripts.

It understands the parts that decide placement - ENTRY, MEMORY, SECTIONS,
output section statements with their address, type, AT()/AT>, > REGION,
input section descriptions (with KEEP and EXCLUDE_FILE), assignments to `.`
and symbols, PROVIDE, ALIGN and /DISCARD/ - and keeps everything else as
opaque statements rather than guessing. It is not a full ld grammar.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field

from .mapfile import Region


@dataclass
class InputRule:
    text: str  # as written: KEEP(*(.isr_vector))
    file_pattern: str  # *, crt0.o, *libc.a:*
    section_patterns: list[str]
    keep: bool
    excluded_files: list[str] = field(default_factory=list)

    def matches(self, file: str, section: str) -> bool:
        base = os.path.basename(file.replace("\\", "/"))
        member = base
        m = re.match(r"(.+\.a)\((.+)\)$", base)
        if m:
            member = f"{m.group(1)}:{m.group(2)}"
            base = m.group(2)
        if not (fnmatch.fnmatchcase(base, self.file_pattern)
                or fnmatch.fnmatchcase(member, self.file_pattern)
                or fnmatch.fnmatchcase(file, self.file_pattern)):
            return False
        if any(fnmatch.fnmatchcase(base, x) or fnmatch.fnmatchcase(member, x)
               for x in self.excluded_files):
            return False
        return any(fnmatch.fnmatchcase(section, p) for p in self.section_patterns)


@dataclass
class Statement:
    kind: str  # "assign" | "rule" | "other"
    text: str
    rule: InputRule | None = None


@dataclass
class OutputStatement:
    name: str
    line: int
    address: str | None = None  # explicit VMA expression
    type: str | None = None  # NOLOAD, COPY, ...
    at: str | None = None  # AT(expr): explicit LMA
    align: str | None = None
    region: str | None = None  # > REGION
    lma_region: str | None = None  # AT> REGION
    phdrs: list[str] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)

    @property
    def rules(self) -> list[InputRule]:
        return [s.rule for s in self.body if s.rule is not None]


@dataclass
class LinkerScript:
    path: str
    entry: str | None = None
    regions: list[Region] = field(default_factory=list)
    outputs: list[OutputStatement] = field(default_factory=list)
    top_statements: list[tuple[int, str]] = field(default_factory=list)  # (line, text)

    def output(self, name: str) -> OutputStatement | None:
        for o in self.outputs:
            if o.name == name:
                return o
        return None

    def rule_for(self, file: str, section: str) -> tuple[OutputStatement, InputRule] | None:
        """The first rule (in script order) that captures this input section.

        That is how the linker assigns input sections: the first matching
        input section description in the whole SECTIONS command wins.
        """
        for o in self.outputs:
            for r in o.rules:
                if r.matches(file, section):
                    return o, r
        return None


# -- tokenizer ---------------------------------------------------------------

# Wildcards (* ? [ ]), slashes and dashes are part of names in linker scripts
# (*(.text*), /DISCARD/, elf32-littlearm), so words are tried before operators;
# an operator only stands alone when surrounded by spaces or punctuation.
_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>/\*.*?\*/|//[^\n]*)
  | (?P<string>"[^"]*")
  | (?P<atgt>AT\s*>)
  | (?P<word>[A-Za-z0-9_.$*?\[\]/\\\-+~!^]+)
  | (?P<op>>>=|<<=|==|!=|<=|>=|&&|\|\||<<|>>|[{}();:,=<>?%&|])
""", re.S | re.X)


@dataclass
class Tok:
    text: str
    line: int


def tokenize(text: str) -> list[Tok]:
    toks: list[Tok] = []
    pos = 0
    line = 1
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"linker script: can't read {text[pos:pos + 20]!r} on line {line}")
        kind = m.lastgroup
        val = m.group(0)
        if kind == "atgt":
            toks.append(Tok("AT>", line))
        elif kind not in ("ws", "comment"):
            toks.append(Tok(val, line))
        line += val.count("\n")
        pos = m.end()
    return toks


# -- expressions (for MEMORY) ------------------------------------------------

def eval_number(expr: str) -> int:
    """Evaluate the constant expressions MEMORY uses: 0x8000000, 64K, 1M, 16K - 0x200."""
    e = expr.strip()

    def num(m: re.Match[str]) -> str:
        n, suf = m.group(1), (m.group(2) or "").upper()
        v = int(n, 0) if not re.fullmatch(r"0\d+", n) else int(n, 8)
        return str(v * {"": 1, "K": 1024, "M": 1024 * 1024, "G": 1024 ** 3}[suf])

    py = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)([kKmMgG])?\b", num, e)
    if not re.fullmatch(r"[\d\s+\-*/()<>]+", py):
        raise ValueError(f"can't evaluate {expr!r} (only constants and + - * / << >> are supported)")
    py = py.replace("/", "//")
    return int(eval(py, {"__builtins__": {}}, {}))  # noqa: S307 - digits and operators only


# -- parser ------------------------------------------------------------------

class _Parser:
    def __init__(self, toks: list[Tok]):
        self.t = toks
        self.i = 0

    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.t[j].text if j < len(self.t) else ""

    def line(self) -> int:
        return self.t[self.i].line if self.i < len(self.t) else (self.t[-1].line if self.t else 0)

    def take(self) -> str:
        tok = self.t[self.i].text
        self.i += 1
        return tok

    def expect(self, s: str) -> None:
        if self.peek() != s:
            raise ValueError(f"linker script line {self.line()}: expected {s!r}, found {self.peek()!r}")
        self.i += 1

    def until(self, stops: set[str]) -> str:
        """Collect tokens (balancing parentheses) until a stop token at depth 0."""
        out: list[str] = []
        depth = 0
        while self.i < len(self.t):
            p = self.peek()
            if depth == 0 and p in stops:
                break
            if p == "(":
                depth += 1
            elif p == ")":
                if depth == 0:
                    break
                depth -= 1
            out.append(self.take())
        return _join(out)

    def group(self) -> str:
        """A parenthesised group, returned without the outer parentheses."""
        self.expect("(")
        inner = self.until({")"})
        self.expect(")")
        return inner


def _join(tokens: list[str]) -> str:
    s = " ".join(tokens)
    s = re.sub(r"\s*\(\s*", "(", s)
    s = re.sub(r"\s*\)", ")", s)
    s = re.sub(r"\s*,\s*", ", ", s)
    return s


def parse(path: str) -> LinkerScript:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"linker script not found: {path}")
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return parse_text(text, path)


def parse_text(text: str, path: str = "<script>") -> LinkerScript:
    ls = LinkerScript(path)
    p = _Parser(tokenize(text))
    while p.i < len(p.t):
        word = p.peek()
        line = p.line()
        if word == "ENTRY":
            p.take()
            ls.entry = p.group()
        elif word == "MEMORY":
            p.take()
            _memory(p, ls)
        elif word == "SECTIONS":
            p.take()
            _sections(p, ls)
        elif word in ("OUTPUT_FORMAT", "OUTPUT_ARCH", "INCLUDE", "SEARCH_DIR", "INPUT", "GROUP",
                      "OUTPUT", "STARTUP", "TARGET", "EXTERN", "PHDRS", "VERSION"):
            p.take()
            if word == "PHDRS" or word == "VERSION":
                body = _skip_block(p)
                ls.top_statements.append((line, f"{word} {{ {body} }}"))
            elif p.peek() == "(":
                ls.top_statements.append((line, f"{word}({p.group()})"))
        elif word == ";":
            p.take()
        else:
            stmt = p.until({";"})
            if p.peek() == ";":
                p.take()
            if stmt:
                ls.top_statements.append((line, stmt))
            else:
                p.take()
    return ls


def _skip_block(p: _Parser) -> str:
    p.expect("{")
    out: list[str] = []
    depth = 1
    while p.i < len(p.t):
        tok = p.take()
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
            if depth == 0:
                break
        out.append(tok)
    return _join(out)


def _memory(p: _Parser, ls: LinkerScript) -> None:
    p.expect("{")
    while p.peek() not in ("}", ""):
        name = p.take()
        attrs = ""
        if p.peek() == "(":
            attrs = p.group().replace(" ", "")
        p.expect(":")
        values: dict[str, int] = {}
        for _ in range(2):
            key = p.take().upper()
            key = {"ORG": "ORIGIN", "O": "ORIGIN", "LEN": "LENGTH", "L": "LENGTH"}.get(key, key)
            p.expect("=")
            values[key] = eval_number(p.until({",", "}"}) if key == "ORIGIN" else p.until({"}"} | _region_starts(p)))
            if p.peek() == ",":
                p.take()
        if "ORIGIN" not in values or "LENGTH" not in values:
            raise ValueError(f"MEMORY region {name}: needs ORIGIN and LENGTH")
        ls.regions.append(Region(name, values["ORIGIN"], values["LENGTH"], attrs))
    p.expect("}")


def _region_starts(p: _Parser) -> set[str]:
    """LENGTH = 16K is followed directly by the next region's name; stop there.

    A region line is `NAME (attrs) : ...` or `NAME : ...`, so a word followed
    by `(` ... `)` `:` or by `:` starts the next region.
    """
    stops: set[str] = set()
    j = p.i
    while j < len(p.t) and p.t[j].text != "}":
        if j + 1 < len(p.t) and p.t[j + 1].text in (":", "("):
            k = j + 1
            if p.t[k].text == "(":
                while k < len(p.t) and p.t[k].text != ")":
                    k += 1
                k += 1
            if k < len(p.t) and p.t[k].text == ":":
                stops.add(p.t[j].text)
        j += 1
    return stops


_OUT_TYPES = {"NOLOAD", "DSECT", "COPY", "INFO", "OVERLAY", "READONLY"}


def _sections(p: _Parser, ls: LinkerScript) -> None:
    p.expect("{")
    while p.peek() not in ("}", ""):
        line = p.line()
        word = p.peek()
        # An output section statement is `name ... :` before the next `;`/`{`.
        if _looks_like_output(p):
            ls.outputs.append(_output(p, line))
        elif word == ";":
            p.take()
        else:
            stmt = p.until({";", "}"})
            if p.peek() == ";":
                p.take()
            if stmt:
                ls.top_statements.append((line, stmt))
            elif p.peek() not in ("}", ""):
                p.take()
    p.expect("}")


def _looks_like_output(p: _Parser) -> bool:
    j = p.i
    depth = 0
    while j < len(p.t):
        tok = p.t[j].text
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
        elif depth == 0:
            if tok in (";", "=", "}", "{"):
                return False
            if tok == ":":
                return True
        j += 1
    return False


def _output(p: _Parser, line: int) -> OutputStatement:
    o = OutputStatement(p.take(), line)
    # [address] [(type)] :
    while p.peek() != ":":
        if p.peek() == "(":
            inner = p.group()
            if inner.upper() in _OUT_TYPES:
                o.type = inner.upper()
            else:
                o.address = inner
        else:
            o.address = p.until({":", "("}) or o.address
    p.expect(":")
    # [AT(lma)] [ALIGN(n)] [SUBALIGN(n)] [constraint]
    while p.peek() != "{":
        word = p.take()
        if word == "AT":
            o.at = p.group()
        elif word in ("ALIGN", "SUBALIGN", "ALIGN_WITH_INPUT"):
            o.align = p.group() if p.peek() == "(" else word
        elif p.peek() == "(":
            p.group()
    p.expect("{")
    o.body = _body(p)
    p.expect("}")
    # > region  AT> region  :phdr  =fill
    while True:
        tok = p.peek()
        if tok == ">":
            p.take()
            o.region = p.take()
        elif tok == "AT>" or (tok == "AT" and p.peek(1) == ">"):
            p.take()
            if tok == "AT":
                p.take()
            o.lma_region = p.take()
        elif tok == ":" and p.peek(1) not in ("",):
            p.take()
            o.phdrs.append(p.take())
        elif tok == "=":
            p.take()
            p.until({";", "}"} | set())
            break
        elif tok == ",":
            p.take()
        else:
            break
    return o


def _body(p: _Parser) -> list[Statement]:
    out: list[Statement] = []
    while p.peek() not in ("}", ""):
        tok = p.peek()
        if tok == ";":
            p.take()
            continue
        start = p.i
        stmt = p.until({";", "}"})
        # An input rule is followed by its next statement with no `;`, so a
        # run like `*(.text*) *(.rodata*)` needs splitting.
        for piece in _split_rules(p.t[start:p.i]):
            out.append(_statement(piece))
        if p.peek() == ";":
            p.take()
        del stmt
    return out


def _split_rules(toks: list[Tok]) -> list[str]:
    pieces: list[list[str]] = [[]]
    depth = 0
    for k, t in enumerate(toks):
        pieces[-1].append(t.text)
        if t.text == "(":
            depth += 1
        elif t.text == ")":
            depth -= 1
            # A rule ends with its closing paren at depth 0, unless an
            # operator follows (an expression like ALIGN(4) + 2).
            nxt = toks[k + 1].text if k + 1 < len(toks) else ""
            # (`*` is not an operator here: it starts the next rule, `*(.x)`.)
            if depth == 0 and nxt and nxt not in ("=", "+", "-", "/", "&", "|", ")", ",") \
                    and "=" not in [x for x in pieces[-1]]:
                pieces.append([])
    return [_join(p) for p in pieces if p]


_RULE = re.compile(r"^(?P<keep>KEEP\()?(?P<file>[^\s(]*?)\s*\((?P<inner>.*)\)\)?$")


def _statement(text: str) -> Statement:
    if "=" in text.replace("==", "") and not text.startswith(("KEEP", "*")) or text.startswith(
            ("PROVIDE", "ASSERT", "HIDDEN", ". =", ".=")):
        return Statement("assign", text)
    rule = _parse_rule(text)
    if rule is not None:
        return Statement("rule", text, rule)
    return Statement("other", text)


def _parse_rule(text: str) -> InputRule | None:
    t = text.strip()
    keep = t.startswith("KEEP(") and t.endswith(")")
    inner = t[5:-1].strip() if keep else t
    for wrap in ("SORT_BY_NAME", "SORT_BY_ALIGNMENT", "SORT_BY_INIT_PRIORITY", "SORT_NONE", "SORT"):
        inner = re.sub(rf"\b{wrap}\(([^()]*)\)", r"\1", inner)
    m = re.match(r"^(?:EXCLUDE_FILE\(([^)]*)\)\s*)?([^\s(]*)\s*\((.*)\)$", inner)
    if not m:
        return None
    excluded = m.group(1).split() if m.group(1) else []
    file_pat = m.group(2) or "*"
    secs = m.group(3)
    ex2 = re.match(r"^EXCLUDE_FILE\(([^)]*)\)\s*(.*)$", secs)
    if ex2:
        excluded += ex2.group(1).split()
        secs = ex2.group(2)
    patterns = [s for s in re.split(r"[\s,]+", secs) if s]
    if not patterns or any(c in file_pat for c in "=;"):
        return None
    if file_pat in ("COMMON",):
        return None
    return InputRule(text, file_pat, patterns, keep, excluded)


# -- plain-English explanation ------------------------------------------------

def explain(ls: LinkerScript) -> str:
    out: list[str] = [f"Linker script {os.path.basename(ls.path)}:"]
    if ls.entry:
        out.append(f"- Execution starts at `{ls.entry}` (ENTRY): the ELF entry point, where "
                   "a bootloader or the reset logic jumps.")
    if ls.regions:
        out.append("- MEMORY declares the address ranges sections may be placed in:")
        for r in ls.regions:
            attrs = f" ({_attrs(r.attributes)})" if r.attributes else ""
            out.append(f"    {r.name}: {r.origin:#x}-{r.end - 1:#x}, {_size(r.length)}{attrs}")
    else:
        out.append("- No MEMORY command: sections are placed by the location counter `.` alone, "
                   "and nothing stops them from overlapping or growing without bound.")
    for line, s in ls.top_statements:
        if s.startswith(". ="):
            out.append(f"- line {line}: `{s}` moves the location counter: the next output section "
                       f"starts at {s[3:].strip()}.")
        elif "=" in s:
            out.append(f"- line {line}: `{s}` defines a symbol the program can reference "
                       "(it has an address but no storage).")
    for o in ls.outputs:
        out.append(_explain_output(o))
    return "\n".join(out)


def _explain_output(o: OutputStatement) -> str:
    if o.name == "/DISCARD/":
        pats = ", ".join(r.text for r in o.rules) or "(nothing)"
        return (f"- /DISCARD/ (line {o.line}): input sections matching {pats} are thrown away - "
                "they never reach the output, even if code references them.")
    parts = [f"- {o.name} (line {o.line}):"]
    if o.address:
        parts.append(f"placed at {o.address}")
    if o.region:
        parts.append(f"runs in {o.region} (VMA)")
    if o.lma_region and o.lma_region != o.region:
        parts.append(f"but is stored in {o.lma_region} (LMA) - startup code must copy it "
                     f"from {o.lma_region} to {o.region} before use")
    elif o.at:
        parts.append(f"stored at AT({o.at}) (LMA differs from VMA - needs a copy at startup)")
    if o.type == "NOLOAD":
        parts.append("NOLOAD: takes address space but no bytes in the image (zeroed or left "
                     "uninitialised at runtime)")
    if o.align:
        parts.append(f"aligned to {o.align}")
    contents = []
    for st in o.body:
        if st.rule is not None:
            r = st.rule
            what = " or ".join(r.section_patterns)
            src = "every input file" if r.file_pattern == "*" else f"files matching {r.file_pattern}"
            keep = " - KEEP: kept even if nothing references it (--gc-sections won't drop it)" \
                if r.keep else ""
            excl = f" except {', '.join(r.excluded_files)}" if r.excluded_files else ""
            contents.append(f"collects {what} from {src}{excl}{keep}")
        elif st.kind == "assign":
            contents.append(_explain_assign(st.text))
    text = " ".join(parts)
    if contents:
        text += "\n    " + "\n    ".join(contents)
    return text


def _explain_assign(s: str) -> str:
    m = re.match(r"^\.\s*=\s*ALIGN\((.+)\)$", s)
    if m:
        return f"`{s}`: pads to the next {m.group(1)}-byte boundary"
    m = re.match(r"^\.\s*=\s*\.\s*\+\s*(.+)$", s)
    if m:
        return f"`{s}`: reserves {m.group(1)} bytes of space here"
    m = re.match(r"^PROVIDE(?:_HIDDEN)?\((\w+)\s*=\s*(.+)\)$", s)
    if m:
        return (f"`{s}`: defines {m.group(1)} only if the program doesn't define it itself "
                f"(here: {m.group(2)})")
    m = re.match(r"^(\w+)\s*=\s*\.$", s)
    if m:
        return f"`{s}`: {m.group(1)} marks this address (current location)"
    m = re.match(r"^(\w+)\s*=\s*LOADADDR\((.+)\)$", s)
    if m:
        return f"`{s}`: {m.group(1)} = where {m.group(2)} is stored (its LMA) - the copy source"
    return f"`{s}`"


def _attrs(a: str) -> str:
    names = {"r": "read", "w": "write", "x": "execute", "a": "allocatable", "i": "initialised",
             "l": "initialised", "!": "not"}
    return ", ".join(names.get(c.lower(), c) for c in a)


def _size(n: int) -> str:
    if n % (1024 * 1024) == 0:
        return f"{n // (1024 * 1024)} MiB"
    if n % 1024 == 0:
        return f"{n // 1024} KiB"
    return f"{n} bytes"
