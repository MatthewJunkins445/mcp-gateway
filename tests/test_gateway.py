from pathlib import Path
import sys
import tempfile
import unittest

from mcp import types

from mcp_gateway.gateway import Gateway, catalog
from mcp_gateway.security import GuardError, digest
from mcp_gateway.state import Audit


class FakeSession:
    def __init__(self):
        self.tool = types.Tool(name="add", description="Add integers", inputSchema={
            "type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"], "additionalProperties": False})
        self.calls = 0
        self.result = types.CallToolResult(content=[types.TextContent(type="text", text="token=fake-secret")])

    async def list_tools(self, cursor=None):
        return types.ListToolsResult(tools=[self.tool])

    async def call_tool(self, name, arguments):
        self.calls += 1
        return self.result


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.session = FakeSession()
        self.spec = {"command": sys.executable, "args": [], "cwd": self.temp.name}
        self.config = {"servers": {"demo": self.spec}, "policy": {"allow": ["demo/add"], "deny": []}}
        definition = self.session.tool.model_dump(mode="json", by_alias=True, exclude_none=True)
        self.pins = {"demo/add": {"definition": definition, "server_digest": digest(self.spec)}}
        self.audit = Audit(Path(self.temp.name) / "audit.jsonl")
        self.gateway = Gateway(self.config, {"demo": self.session}, self.pins, self.audit)

    async def test_list_and_redacted_call(self):
        self.assertEqual([tool.name for tool in await self.gateway.list_tools()], ["demo__add"])
        result = await self.gateway.call_tool("demo__add", {"a": 1})
        self.assertFalse(result.isError)
        self.assertEqual(result.content[0].text, "[REDACTED]")
        self.assertEqual(self.session.calls, 1)

    async def test_mutation_between_list_and_call(self):
        await self.gateway.list_tools()
        self.session.tool.description = "New malicious instruction"
        result = await self.gateway.call_tool("demo__add", {"a": 1})
        self.assertTrue(result.isError)
        self.assertEqual(self.session.calls, 0)
        self.assertEqual(await self.gateway.list_tools(), [])

    async def test_direct_unknown_and_denied_calls(self):
        self.config["policy"]["deny"] = ["demo/add"]
        for name in ("demo__add", "demo__missing", "other__add", "unqualified"):
            self.assertTrue((await self.gateway.call_tool(name, {"a": 1})).isError)
        self.assertEqual(self.session.calls, 0)

    async def test_invalid_arguments_do_not_leak(self):
        result = await self.gateway.call_tool("demo__add", {"a": "sensitive-value"})
        self.assertTrue(result.isError)
        self.assertNotIn("sensitive-value", result.model_dump_json())
        self.assertNotIn("sensitive-value", self.audit.path.read_text())
        self.assertEqual(self.session.calls, 0)

    async def test_upstream_exception_is_not_forwarded(self):
        async def broken(*args):
            raise RuntimeError("secret-raw-exception")
        self.session.call_tool = broken
        result = await self.gateway.call_tool("demo__add", {"a": 1})
        self.assertNotIn("secret-raw-exception", result.model_dump_json())
        self.assertNotIn("secret-raw-exception", self.audit.path.read_text())

    async def test_nontext_content_blocks(self):
        self.session.result.content = [types.ImageContent(type="image", data="ZmFrZQ==", mimeType="image/png")]
        self.assertTrue((await self.gateway.call_tool("demo__add", {"a": 1})).isError)

    async def test_metadata_removed_and_structured_secrets_redacted(self):
        self.session.result = types.CallToolResult(content=[types.TextContent(type="text", text="safe", _meta={"secret": "raw"})],
                                                 structuredContent={"token": "raw"}, _meta={"secret": "raw"})
        result = await self.gateway.call_tool("demo__add", {"a": 1})
        self.assertNotIn("raw", result.model_dump_json())
        self.assertEqual(result.structuredContent, {"token": "[REDACTED]"})

    async def test_redaction_schema_conflict_blocks(self):
        self.session.tool.outputSchema = {"type": "object", "properties": {"token": {"const": "raw"}}, "required": ["token"]}
        self.pins["demo/add"]["definition"] = self.session.tool.model_dump(mode="json", by_alias=True, exclude_none=True)
        self.session.result.structuredContent = {"token": "raw"}
        self.assertTrue((await self.gateway.call_tool("demo__add", {"a": 1})).isError)

    async def test_audit_failure_prevents_upstream_execution(self):
        self.audit.failed = True
        with self.assertRaises(GuardError):
            await self.gateway.call_tool("demo__add", {"a": 1})
        self.assertEqual(self.session.calls, 0)

    async def test_duplicate_tools_and_repeating_cursor_rejected(self):
        async def duplicate(cursor=None):
            return types.ListToolsResult(tools=[self.session.tool, self.session.tool])
        self.session.list_tools = duplicate
        with self.assertRaises(GuardError):
            await catalog(self.session)
        async def repeat(cursor=None):
            return types.ListToolsResult(tools=[], nextCursor="same")
        self.session.list_tools = repeat
        with self.assertRaises(GuardError):
            await catalog(self.session)

    async def test_pagination_collects_all_pages(self):
        async def pages(cursor=None):
            return types.ListToolsResult(tools=[] if cursor else [self.session.tool], nextCursor=None if cursor else "last")
        self.session.list_tools = pages
        self.assertEqual(list(await catalog(self.session)), ["add"])
