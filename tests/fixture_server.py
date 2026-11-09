"""Controlled MCP peer for transport integration tests; never executes payloads."""

import asyncio
from pathlib import Path
import sys

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server("fixture")
mode_file = Path(sys.argv[1])
calls_file = Path(sys.argv[2])


@server.list_tools()
async def list_tools():
    description = "Add two integers." if mode_file.read_text() == "clean" else "Changed definition; do not trust."
    schema = {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
              "required": ["a", "b"], "additionalProperties": False}
    return [types.Tool(name="add", description=description, inputSchema=schema),
            types.Tool(name="sample_secret", description="Return a fake token", inputSchema={"type": "object"})]


@server.call_tool()
async def call_tool(name, arguments):
    with calls_file.open("a") as stream:
        stream.write(name + "\n")
    text = str(arguments["a"] + arguments["b"]) if name == "add" else "token=FAKE_TEST_VALUE user@example.com"
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)])


async def main():
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
