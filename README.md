# MCP gateway

A local Python studio proxy that exposes only explicitly allowed tools whose definitions match an operator-approved lock file.

Status: working first version, with unit tests, a real MCP transport integration test, and a small reproducible policy evaluation. This is a change-control boundary, not a semantic prompt-injection detector or a sandbox for malicious server processes.

## Start here

- [Design and security boundaries](docs/design.md)
- [Research sources and evaluation results](docs/evaluation.md)
- [Handoff, verification, and next steps](docs/handoff.md)

```text
Agent --stdio--> Gateway --stdio--> Configured MCP server processes
                    |
                    +-- exact per-tool allow/deny policy
                    +-- approved tools.lock.json
                    +-- response redaction
                    +-- hash-chained audit.jsonl
```

The gateway supports multiple configured local servers. Tools appear as `server__tool`; policy and approval commands use `server/tool`. Deny overrides allow. There are no wildcard grants or automatic first-use approvals.

## Install and try the demo

Python 3.11+ is required. From this project folder, use the committed dependency lock:

```powershell
uv sync --locked
Copy-Item examples/gateway.example.json gateway.json
```

Edit `gateway.json`: set `command` to the absolute path of `.venv/Scripts/python.exe` on Windows (or `.venv/bin/python` on Unix), and set `args` and `cwd` to the actual project paths. The example contains harmless demo tools. Allow entries alone do not enable tools: pins are required too.

```powershell
uv run mcp-gateway discover
uv run mcp-gateway diff
```

Read the entire diff as untrusted data. In particular, inspect descriptions inside schemas, titles, annotations, and extra metadata. The diff escapes control characters and non-ASCII characters so invisible text is visible. The candidate file is local and may itself contain sensitive or hostile metadata; do not paste it unreviewed into an agent.

Copy the candidate digest printed by `diff` into these commands after review:

```powershell
uv run mcp-gateway approve --tool demo/add --digest REVIEWED_CANDIDATE_DIGEST
uv run mcp-gateway approve --tool demo/sample_secret --digest REVIEWED_CANDIDATE_DIGEST
uv run mcp-gateway serve
```

If approval reports `Candidate changed; review its diff again`, the supplied digest does not match the current candidate. Run `diff` again, review it, and copy its full digest. Use the printed candidate digest, not a file hash from another command. Rediscovery can replace the candidate, making a previously copied digest stale. If `diff` or `approve` reports `No candidate found`, run `discover` first.

`serve` speaks MCP on stdin/stdout and waits for a client; it is not an interactive shell. Approval is a local operator action, never an MCP tool exposed to the agent. Stop the gateway before discovery, approval, revocation, verification, or policy edits. Restart after changes: running processes retain their startup policy and pins. A single-writer state lock prevents overlapping gateway/CLI instances using the same state directory.

For clients supporting `mcpServers` configuration, adapt these paths:

```json
{
  "mcpServers": {
    "gateway": {
      "command": "F:/Personal_Projects/mcp-gateway/.venv/Scripts/python.exe",
      "args": [
        "-m", "mcp_gateway.cli",
        "--config", "F:/Personal_Projects/mcp-gateway/gateway.json",
        "--state", "F:/Personal_Projects/mcp-gateway/.gateway",
        "serve"
      ]
    }
  }
}
```

Configure the agent to use the gateway entry. Direct connections to the original servers bypass its controls. This project does not change your installed agent configuration automatically.

## Operator commands

| Command | Effect |
| --- | --- |
| `discover` | Starts configured servers and writes a candidate catalog; approves nothing |
| `diff` | Shows the candidate against approved pins, with its digest |
| `approve --tool server/tool --digest SHA256` | Approves one tool from that exact reviewed candidate |
| `revoke --tool server/tool` | Removes one approved pin |
| `serve` | Starts the stdio gateway |
| `verify-audit [--head SHA256]` | Verifies chain integrity and optionally an externally saved final hash |

Global `--config PATH` and `--state DIRECTORY` options go before the command. Files default to `gateway.json` and `.gateway/` in the working directory. Keep the lock file under your chosen review/version-control workflow; `.gateway/` is ignored by default to avoid committing sensitive catalogs and audit records inadvertently.

## What is enforced

- The complete tool definition and configured executable/arguments/working directory must match the approved pin. Object key ordering is ignored; string content, types, arrays, and metadata changes are significant.
- Listing hides unapproved, denied, or changed tools. Calls refresh the upstream catalog and enforce the same rules even if a client guesses a hidden tool name.
- Input JSON is validated against the pinned schema. External schema references are rejected. Tool calls and paginated catalog reads have timeouts.
- Text responses redact common token formats, private key blocks, bearer tokens, common secret assignments, and email addresses. Structured JSON is recursively redacted, including values of sensitive field names. `secret_env` lists environment variables whose exact values must also be removed; missing or empty values stop startup. It does not forward these variables to upstream processes.
- Binary/resource content is rejected because this version cannot inspect it. Upstream result metadata is removed. If redaction makes structured output violate its declared schema, the response is withheld.
- Audit records contain decisions, hashes, timestamps, and counts, without raw call arguments or responses. Audit write failures prevent further successful forwarding. Upstream exception text and stderr are not relayed to the client.

Redaction is deliberately limited. It can miss encoded, fragmented, unfamiliar, or contextual secrets and can redact harmless text. It is not comprehensive PII removal. Tool arguments are sent to allowed upstreams after schema validation; this version does not perform outbound DLP.

## Run checks

```powershell
uv run python -m unittest discover -s tests -v
uv run python -m evaluation.run --output evaluation/results.json
```

The fixtures use fake credentials and reserved example domains. No malware runs and no LLM account is required. See the [evaluation explanation](docs/evaluation.md) before citing any percentages.

## License

[MIT](LICENSE). Research fixtures are original paraphrases with source attribution, not copied published datasets.
