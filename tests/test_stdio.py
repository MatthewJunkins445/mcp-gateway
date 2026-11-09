from contextlib import asynccontextmanager
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_gateway.state import Audit, read_json, write_json
from mcp_gateway.security import digest

ROOT = Path(__file__).resolve().parents[1]


class StdioIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.mode = self.root / "mode.txt"
        self.calls = self.root / "calls.txt"
        self.mode.write_text("clean")
        self.config_path = self.root / "gateway.json"
        self.config = {
            "servers": {"demo": {"command": sys.executable, "args": [str(ROOT / "tests" / "fixture_server.py"),
                                                                     str(self.mode), str(self.calls)], "cwd": str(ROOT)}},
            "policy": {"allow": ["demo/add", "demo/sample_secret"], "deny": []}, "secret_env": []}
        write_json(self.config_path, self.config)
        self.base = [sys.executable, "-m", "mcp_gateway.cli", "--config", str(self.config_path), "--state", str(self.state)]

    async def cli(self, *args, success=True):
        process = await asyncio.to_thread(subprocess.run, [*self.base, *args], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode == 0, success, process.stderr)
        return process.stdout

    @asynccontextmanager
    async def client(self):
        with open(os.devnull, "w") as errors:
            params = StdioServerParameters(command=self.base[0], args=[*self.base[1:], "serve"], cwd=str(ROOT))
            async with stdio_client(params, errlog=errors) as streams:
                async with ClientSession(*streams, read_timeout_seconds=timedelta(seconds=20)) as session:
                    await session.initialize()
                    yield session

    async def test_complete_operator_and_agent_workflow(self):
        await self.cli("discover")
        self.assertFalse((self.state / "tools.lock.json").exists())
        async with self.client() as client:
            self.assertEqual((await client.list_tools()).tools, [])
            self.assertTrue((await client.call_tool("demo__add", {"a": 2, "b": 3})).isError)
        self.assertFalse(self.calls.exists())
        diff = await self.cli("diff")
        self.assertIn("Add two integers", diff)
        candidate_digest = digest(read_json(self.state / "candidate.json"))
        await self.cli("approve", "--tool", "demo/add", "--digest", "wrong", success=False)
        self.assertFalse((self.state / "tools.lock.json").exists())
        for name in ("add", "sample_secret"):
            await self.cli("approve", "--tool", f"demo/{name}", "--digest", candidate_digest)
        async with self.client() as client:
            self.assertEqual({tool.name for tool in (await client.list_tools()).tools}, {"demo__add", "demo__sample_secret"})
            result = await client.call_tool("demo__add", {"a": 2, "b": 3})
            self.assertFalse(result.isError)
            self.assertEqual(result.content[0].text, "5")
            result = await client.call_tool("demo__sample_secret", {})
            self.assertEqual(result.content[0].text, "[REDACTED] [REDACTED]")
            self.mode.write_text("changed")
            self.assertTrue((await client.call_tool("demo__add", {"a": 2, "b": 3})).isError)
            self.assertEqual([tool.name for tool in (await client.list_tools()).tools], ["demo__sample_secret"])
        self.assertEqual(self.calls.read_text().splitlines(), ["add", "sample_secret"])
        self.mode.write_text("clean")
        self.config["policy"]["deny"] = ["demo/add"]
        write_json(self.config_path, self.config)
        async with self.client() as client:
            self.assertTrue((await client.call_tool("demo__add", {"a": 1, "b": 1})).isError)
        await self.cli("revoke", "--tool", "demo/sample_secret")
        self.assertNotIn("demo/sample_secret", read_json(self.state / "tools.lock.json")["tools"])
        verification = json.loads(await self.cli("verify-audit"))
        await self.cli("verify-audit", "--head", verification["head"])
        await self.cli("verify-audit", "--head", "0" * 64, success=False)
        self.assertNotIn("FAKE_TEST_VALUE", (self.state / "audit.jsonl").read_text())
        self.assertGreater(Audit.verify(self.state / "audit.jsonl")[0], 10)
