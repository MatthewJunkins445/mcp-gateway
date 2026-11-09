"""MCP transport boundary; unapproved metadata never reaches the client."""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import timedelta
import os
from pathlib import Path
import re

from jsonschema import Draft202012Validator
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .security import GuardError, canonical, check_pin, digest, redact, redact_text, validate_schema
from .state import read_json

MAX_DEFINITION_BYTES = 256_000
MAX_RESULT_BYTES = 1_000_000
MAX_TOOLS = 1_000
TIMEOUT = 15
NAME = re.compile(r"[A-Za-z0-9_.-]{1,60}\Z")


def load_config(path):
    config = read_json(path)
    if set(config) - {"servers", "policy", "secret_env"} or not isinstance(config.get("servers"), dict) or not config["servers"]:
        raise GuardError("Config requires servers and policy")
    policy = config.get("policy", {})
    if set(policy) != {"allow", "deny"}:
        raise GuardError("Policy requires explicit allow and deny lists")
    for values in policy.values():
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
            raise GuardError("Policy entries must be strings")
    for alias, spec in config["servers"].items():
        if not NAME.fullmatch(alias) or "__" in alias or not isinstance(spec, dict):
            raise GuardError("Invalid server alias or configuration")
        if set(spec) != {"command", "args", "cwd"}:
            raise GuardError("Each server requires command, args, and cwd; use environment variables for secrets")
        if not isinstance(spec["command"], str) or not Path(spec["command"]).is_absolute():
            raise GuardError("Server command must be an absolute executable path")
        if not isinstance(spec["cwd"], str) or not Path(spec["cwd"]).is_absolute():
            raise GuardError("Server cwd must be absolute")
        if not isinstance(spec["args"], list) or any(not isinstance(arg, str) for arg in spec["args"]):
            raise GuardError("Server args must be a list of strings")
    for key in policy["allow"] + policy["deny"]:
        parts = key.split("/", 1)
        if len(parts) != 2 or parts[0] not in config["servers"] or not NAME.fullmatch(parts[1]):
            raise GuardError("Policy tools must use configured-server/tool names; wildcards are unsupported")
    names = config.get("secret_env", [])
    if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
        raise GuardError("secret_env must list environment variable names")
    if any(not os.environ.get(name) for name in names):
        raise GuardError("A configured secret environment variable is missing or empty")
    return config


@asynccontextmanager
async def connect(config):
    async with AsyncExitStack() as stack:
        errors = stack.enter_context(open(os.devnull, "w"))
        sessions = {}
        for alias, spec in config["servers"].items():
            streams = await stack.enter_async_context(stdio_client(StdioServerParameters(**spec), errlog=errors))
            session = await stack.enter_async_context(ClientSession(*streams, read_timeout_seconds=timedelta(seconds=TIMEOUT)))
            await session.initialize()
            sessions[alias] = session
        yield sessions


async def catalog(session):
    found, cursors, cursor = {}, set(), None
    async with asyncio.timeout(TIMEOUT):
        while True:
            page = await session.list_tools(cursor=cursor)
            for tool in page.tools:
                definition = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                if not NAME.fullmatch(tool.name) or tool.name in found:
                    raise GuardError("Invalid or duplicate tool name")
                if len(canonical(definition).encode()) > MAX_DEFINITION_BYTES:
                    raise GuardError("Tool definition exceeds the size limit")
                validate_schema(tool.inputSchema)
                if tool.outputSchema is not None:
                    validate_schema(tool.outputSchema)
                found[tool.name] = definition
                if len(found) > MAX_TOOLS:
                    raise GuardError("Tool catalog exceeds the size limit")
            cursor = page.nextCursor
            if cursor is None:
                return found
            if cursor in cursors or len(cursors) >= MAX_TOOLS:
                raise GuardError("Invalid catalog pagination")
            cursors.add(cursor)


def load_pins(path):
    if not Path(path).exists():
        return {}
    data = read_json(path)
    if set(data) != {"version", "tools"} or data["version"] != 1 or not isinstance(data["tools"], dict):
        raise GuardError("Invalid lock file")
    for pin in data["tools"].values():
        if set(pin) != {"definition", "server_digest"} or not isinstance(pin["definition"], dict):
            raise GuardError("Invalid pin")
        if not re.fullmatch(r"[a-f0-9]{64}", pin["server_digest"]):
            raise GuardError("Invalid server digest")
        tool = types.Tool.model_validate(pin["definition"])
        validate_schema(tool.inputSchema)
        if tool.outputSchema is not None:
            validate_schema(tool.outputSchema)
    return data["tools"]


class Gateway:
    def __init__(self, config, sessions, pins, audit):
        self.config, self.sessions, self.pins, self.audit = config, sessions, pins, audit
        self.literals = tuple(os.environ[name] for name in config.get("secret_env", []))
        self.mutex = asyncio.Lock()

    def check(self, alias, name, definition):
        key = f"{alias}/{name}"
        check_pin(key, definition, digest(self.config["servers"][alias]), self.pins, self.config["policy"])

    async def list_tools(self):
        async with self.mutex:
            tools = []
            for alias, session in self.sessions.items():
                try:
                    definitions = await catalog(session)
                except Exception:
                    self.audit.append("catalog_unavailable", server=alias)
                    continue
                for name, definition in definitions.items():
                    try:
                        self.check(alias, name, definition)
                    except GuardError:
                        self.audit.append("tool_hidden", tool=f"{alias}/{name}")
                        continue
                    tools.append(types.Tool.model_validate({**definition, "name": f"{alias}__{name}"}))
            self.audit.append("catalog_served", count=len(tools))
            return tools

    async def call_tool(self, public_name, arguments):
        async with self.mutex:
            # Never put raw arguments, responses, or upstream exception strings in audit records.
            call_id = digest({"name": public_name})
            self.audit.append("call_requested", tool_hash=call_id)
            forwarded = False
            try:
                alias, name = public_name.split("__", 1)
                session = self.sessions[alias]
                definitions = await catalog(session)
                definition = definitions[name]
                self.check(alias, name, definition)
                if len(canonical(arguments).encode()) > MAX_RESULT_BYTES:
                    raise GuardError("Arguments exceed the size limit")
                Draft202012Validator(definition["inputSchema"]).validate(arguments)
                self.audit.append("call_forwarded", tool_hash=call_id)
                forwarded = True
                async with asyncio.timeout(TIMEOUT):
                    result = await session.call_tool(name, arguments)
                if len(result.model_dump_json().encode()) > MAX_RESULT_BYTES:
                    raise GuardError("Response exceeds the size limit")
                if any(block.type != "text" for block in result.content):
                    raise GuardError("Only text and structured JSON responses are supported")
                content = [types.TextContent(type="text", text=redact_text(block.text, self.literals)) for block in result.content]
                structured = redact(result.structuredContent, self.literals)
                if definition.get("outputSchema") is not None and not result.isError:
                    Draft202012Validator(definition["outputSchema"]).validate(structured)
                sanitized = types.CallToolResult(content=content, structuredContent=structured, isError=result.isError)
                self.audit.append("call_completed", tool_hash=call_id, upstream_error=result.isError,
                                  redacted=sanitized != result)
                return sanitized
            except Exception:
                self.audit.append("call_failed" if forwarded else "call_blocked", tool_hash=call_id)
                return types.CallToolResult(isError=True, content=[types.TextContent(
                    type="text", text="Gateway blocked the call or could not safely return its result. Check the local audit log.")])


async def serve(config, state, audit):
    pins = load_pins(state / "tools.lock.json")
    async with connect(config) as sessions:
        gateway = Gateway(config, sessions, pins, audit)
        server = Server("mcp-gateway")

        @server.list_tools()
        async def list_tools():
            try:
                return await gateway.list_tools()
            except Exception:
                return []

        # Validate inside the boundary so SDK errors cannot echo secret arguments.
        @server.call_tool(validate_input=False)
        async def call_tool(name, arguments):
            try:
                return await gateway.call_tool(name, arguments)
            except Exception:
                return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text="Gateway unavailable.")])

        audit.append("gateway_started")
        async with stdio_server() as streams:
            await server.run(*streams, server.create_initialization_options())
