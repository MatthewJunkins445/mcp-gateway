# Design and security boundaries

[Project README](../README.md)

## Agreed scope and implementation plan

The user selected Python and a local stdio gateway. The project lives separately in `F:/Personal_Projects/mcp-gateway`.

1. Use the official MCP SDK for both agent-facing server and upstream clients.
2. Discover complete tool definitions into a candidate file, show a diff, and require an exact candidate digest for per-tool approval.
3. Keep approvals separate from per-tool policy: a valid pin and an explicit allow entry are both necessary; deny wins.
4. Check tool definitions at listing and immediately before forwarding each call.
5. Validate arguments, redact supported responses, and withhold output that cannot safely preserve protocol/schema shape.
6. Record decisions in a hash chain and verify behavior with unit tests, real stdio transport, and attack-inspired fixtures.

Implementation reaches the CLI, transport handlers, state files, policy/configuration, response sanitization, demo server, tests, evaluation fixtures, package metadata, and documentation. There are no callers in the existing workflow-injection-guard project; that project is untouched.

## Module responsibilities

| File | Responsibility |
| --- | --- |
| [cli.py](../mcp_gateway/cli.py) | Operator workflow and startup |
| [gateway.py](../mcp_gateway/gateway.py) | Config validation, upstream connections, catalog checks, forwarding |
| [security.py](../mcp_gateway/security.py) | Canonical hashes, policy checks, schema restrictions, redaction |
| [state.py](../mcp_gateway/state.py) | Atomic JSON replacement, process locking, audit chain |

Each pin contains the full tool definition and a hash of the server command, arguments, and working directory. The lock file stores definitions rather than just hashes so operators can review later changes. The candidate digest binds approval to the exact reviewed candidate, but it is not a digital signature or identity proof.

Commands are executed through the SDK as an executable plus argument list, without a command shell. Executable paths and working directories must be absolute. Server aliases cannot contain `__`, keeping public tool names unambiguous. Unsupported protocol capabilities such as prompts, resources, sampling, and elicitation are not proxied. Upstream initialization instructions are not copied into the agent-facing initialization result.

## Trust model

The operator, gateway files, Python environment, configuration, pins, and operating system account are trusted. Upstream metadata and results can be hostile. The agent is assumed to connect through this gateway and not edit its state or bypass it.

Running a local MCP server executes its program before catalog review. Discovery is not safe execution of unknown software. A server process with the same OS permissions can access the filesystem or network independently, including gateway state. Use OS-level isolation and separate permissions for adversarial programs; this gateway does not supply them.

Pinning detects observed definition changes. It cannot establish that approved prose is harmless, that tool code matches its description, or that server behavior remained unchanged. A server may return an approved definition during checks and perform different actions during a call. Rechecking narrows accidental stale-catalog exposure but does not close this semantic gap.

Redaction happens after the upstream has executed. It cannot undo side effects or prevent upstream exfiltration. Output-based prompt injection is not classified. An approved tool that returns malicious instructions without recognizable secrets may still influence an agent.

## Audit guarantees

The application appends JSONL records containing sequence numbers, timestamps, a previous-record hash, and a SHA-256 hash of the current record. Ordinary edits, middle deletion, reordering, and corruption are detectable. Writes are flushed and synced; on failure the current audit instance remains unusable, and calls fail closed.

This is **tamper-evident, not immutable**. Someone able to rewrite the entire log can recompute an unkeyed chain. Tail deletion or total deletion is not detectable without an independently retained checkpoint. Save the output of `verify-audit` outside the gateway's trust boundary and compare with `--head` for a closed log. Production-grade historical attestation needs an external append-only or retention-locked sink; it is not implemented here.

Approvals and revocations record intent before atomic replacement and completion after it. A crash can leave an intent without a completion; inspect the saved lock to determine whether the change committed. A forwarded call without a completion can have executed upstream. There is no automatic retry, because retrying could duplicate side effects.

## Operational bounds

Calls are serialized. Each call fetches the upstream catalog again; work scales with catalog size. This is appropriate for a small local gateway, not an 800-server fleet. Catalogs are limited to 1,000 tools and 1,000 pagination transitions; individual serialized definitions to 256 KB; arguments/results to 1 MB; catalog collection and tool execution to 15 seconds.

Size checks occur after SDK parsing, so they are not hard wire-level memory limits. Deep schemas and expensive JSON Schema regexes may consume CPU before an asynchronous timeout can interrupt them. CPU/memory isolation and byte-limited framing would be needed for hostile server availability guarantees. Audit startup verification scans the existing log; there is no rotation or retention policy yet.

Only one process may use a state directory at a time. Policy and approval changes require restart. Upstream stderr is discarded to avoid relaying secrets; test a failing server separately with fake data to diagnose it. This version intentionally favors fail-closed behavior over transparent compatibility with every MCP server.
