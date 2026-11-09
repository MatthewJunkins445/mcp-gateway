"""Harmless demo server. Uses fake values only."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


@mcp.tool()
def sample_secret() -> str:
    """Return a fake token and email for the redaction demo."""
    return "token=demo-only-secret contact=demo@example.com"


if __name__ == "__main__":
    mcp.run(transport="stdio")
