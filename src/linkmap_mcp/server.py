"""linkmap-mcp: an MCP server that explains where code and data landed in a
linked binary, and why."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import script as scriptmod
from .analysis import Linked, LinkError

mcp = MCPServer(
    "linkmap",
    instructions=(
        "Explain the memory layout of a linked binary (kernel, firmware, bootloader). "
        "link_load an ELF, ideally with its map file (-Wl,-Map=out.map, GNU ld or lld) and "
        "linker script. Then: link_where <symbol|address> explains WHY something landed "
        "where it did (input section -> script rule -> output section -> segment -> MEMORY "
        "region, plus any FLASH->RAM copy); link_overlaps finds overlaps, overflows, orphan "
        "sections and copy loops startup code must do; link_biggest answers 'what is eating "
        "my flash'; link_diff compares two builds; link_layout shows segments and region "
        "usage; link_script_explain reads a linker script in plain English."
    ),
)

_sessions: dict[str, Linked] = {}

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message
# to the client - anything else arrives as a bare "Error executing tool X" -
# so these are re-raised as ToolError with their text intact. Anything not
# listed here is a genuine bug and stays hidden from the client.
_EXPECTED = (LinkError, KeyError, ValueError, FileNotFoundError, OSError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            # KeyError's str() wraps the message in quotes; use the raw text.
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(str(msg)) from e

    mcp.tool()(wrapper)
    return fn


def _get(name: str) -> Linked:
    s = _sessions.get(name)
    if s is None:
        known = ", ".join(sorted(_sessions)) or "none"
        raise LinkError(f"no binary loaded as {name!r} (loaded: {known}) - call link_load first")
    return s


@tool
def link_load(name: str, elf: str, map: str | None = None, script: str | None = None) -> str:
    """Load a linked ELF under `name`, with its map file and linker script if you have them.

    map: the linker map (-Wl,-Map=out.map). GNU ld and lld formats are both
    understood; it adds which object file / input section every byte came from.
    script: the linker script (-T file.ld); it adds MEMORY regions and the rule
    that placed each section. The ELF alone already gives sections, segments,
    symbols and load addresses. Re-loading a name replaces it.
    """
    linked = Linked(name, elf, map, script)
    _sessions[name] = linked
    e = linked.elf
    lines = [f"Loaded {name!r}: {linked.sources()}",
             f"{e.machine} {e.bits}-bit, {len(e.alloc_sections)} allocated sections, "
             f"{len([s for s in e.segments if s.loadable])} LOAD segments, {len(e.symbols)} symbols"]
    if linked.map is not None:
        m = linked.map
        lines.append(f"map: {len(m.inputs())} input sections from "
                     f"{len({i.file for _, i in m.inputs()})} files"
                     + (f", {len(m.discarded)} discarded" if m.discarded else ""))
    if linked.regions:
        lines.append("regions: " + ", ".join(
            f"{u.region.name} {100 * u.used / u.region.length:.1f}% used" for u in linked.region_usage()))
    problems = linked.problems()
    if not problems.startswith("No "):
        lines.append(f"{len(problems.splitlines())} things worth a look - call link_overlaps.")
    return "\n".join(lines)


@tool
def link_unload(name: str) -> str:
    """Forget a loaded binary."""
    _get(name)
    del _sessions[name]
    return f"Unloaded {name!r}."


@tool
def link_sessions() -> str:
    """List loaded binaries."""
    if not _sessions:
        return "Nothing loaded - call link_load."
    return "\n".join(f"{n}: {s.sources()}" for n, s in _sessions.items())


@tool
def link_layout(name: str) -> str:
    """Segments (what a loader maps) with the sections inside each, their VMA,
    LMA, file and memory sizes; gaps between sections; and usage of every
    MEMORY region (code and load images in FLASH, data in RAM)."""
    return _get(name).layout()


@tool
def link_where(name: str, query: str) -> str:
    """Explain why a symbol or address is where it is.

    query: a symbol (kmain), symbol+offset (kmain+0x10), an output section
    (.data), or an address (0x20000004 - including an address inside a load
    image in FLASH). Walks the chain: object file and input section (needs the
    map) -> the linker-script rule that captured it -> output section -> LOAD
    segment -> MEMORY region and load address, with the copy startup code must
    do when LMA != VMA. Flags orphan sections the script never mentions.
    """
    return _get(name).where(query)


@tool
def link_overlaps(name: str) -> str:
    """Find layout problems: overlapping sections (VMA or stored bytes) or
    segments, sections outside or straddling MEMORY regions, overflowing and
    nearly-full (>=90%) regions, RWX segments, orphan sections the script
    doesn't name, discarded input sections (GNU map), and every LMA != VMA
    section with the exact copy (dest, source, length) startup code must do."""
    return _get(name).problems()


@tool
def link_biggest(name: str, by: str = "symbol", limit: int = 15, region: str | None = None) -> str:
    """What is eating the space. by: "symbol", "input" (input section + file,
    needs map), "object" (per object/library member, needs map) or "section".
    region (e.g. "FLASH") counts only what runs or is stored there - a
    FLASH-resident load image of .data counts towards FLASH."""
    if not 1 <= limit <= 200:
        raise LinkError("limit must be between 1 and 200")
    return _get(name).biggest(by, limit, region)


@tool
def link_diff(old: str, new: str) -> str:
    """Compare two loaded builds: output-section and region size changes
    (with how full each region is now), and new, removed and resized symbols."""
    return _get(old).diff(_get(new))


@tool
def link_script_explain(script: str | None = None, name: str | None = None) -> str:
    """Read a linker script in plain English: ENTRY, MEMORY regions, where each
    output section runs and is stored (> REGION, AT> REGION, AT()), what each
    input rule collects, KEEP, PROVIDE, ALIGN, location-counter moves and
    /DISCARD/. Pass a path (script=) or a loaded binary's name (name=)."""
    if script is not None:
        ls = scriptmod.parse(script)
    elif name is not None:
        linked = _get(name)
        if linked.script is None:
            raise LinkError(f"{name!r} was loaded without a linker script - pass script= to link_load")
        ls = linked.script
    else:
        raise LinkError("pass script= (a path) or name= (a loaded binary)")
    return scriptmod.explain(ls)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()


