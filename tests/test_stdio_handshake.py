"""MCP over real stdio: the tool list, a full tool call, and that instructive
errors reach the client (mcp 2 hides non-ToolError exceptions)."""

import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

from conftest import fx  # noqa: E402

EXPECTED_TOOLS = {
    "link_load",
    "link_unload",
    "link_sessions",
    "link_layout",
    "link_where",
    "link_overlaps",
    "link_biggest",
    "link_diff",
    "link_script_explain",
}

PARAMS = StdioServerParameters(command=sys.executable, args=["-m", "linkmap_mcp"])


@pytest.mark.anyio
async def test_tool_list():
    async with stdio_client(PARAMS) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "linkmap"
        names = {t.name for t in (await session.list_tools()).tools}
        assert names == EXPECTED_TOOLS, (names - EXPECTED_TOOLS, EXPECTED_TOOLS - names)


@pytest.mark.anyio
async def test_load_and_where_over_stdio():
    async with stdio_client(PARAMS) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("link_load", {
            "name": "fw", "elf": fx("embedded", "firmware-gnu.elf"),
            "map": fx("embedded", "firmware-gnu.map"), "script": fx("embedded", "link.ld")})
        assert not res.is_error and "gnu map" in res.content[0].text
        res = await session.call_tool("link_where", {"name": "fw", "query": "boot_count"})
        assert not res.is_error and "AT> FLASH" in res.content[0].text


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent():
    async with stdio_client(PARAMS) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("link_where", {"name": "nope", "query": "main"})
        assert res.is_error
        assert "no binary loaded as 'nope'" in res.content[0].text
        assert "call link_load first" in res.content[0].text
        res = await session.call_tool("link_load", {"name": "x", "elf": "missing.elf"})
        assert res.is_error and "ELF not found: missing.elf" in res.content[0].text
