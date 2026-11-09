"""Operator-only discovery, review, approval, and stdio serving."""

import argparse
import asyncio
import difflib
import json
from pathlib import Path
import sys

from .gateway import catalog, connect, load_config, load_pins, serve
from .security import GuardError, digest
from .state import Audit, exclusive_state, read_json, write_json


async def discover(config, state, audit):
    tools = {}
    async with connect(config) as sessions:
        for alias, session in sessions.items():
            for name, definition in (await catalog(session)).items():
                tools[f"{alias}/{name}"] = {"definition": definition, "server_digest": digest(config["servers"][alias])}
    candidate = {"version": 1, "tools": tools}
    audit.append("discovery", candidate_digest=digest(candidate), count=len(tools))
    write_json(state / "candidate.json", candidate)
    print("Candidate digest:", digest(candidate))
    print("Review with diff. Discovery does not approve tools.")


def read_candidate(state):
    if not (state / "candidate.json").exists():
        raise GuardError("No candidate found; run discover first")
    return read_json(state / "candidate.json")


def main():
    parser = argparse.ArgumentParser(description="Local MCP tool-pinning gateway")
    parser.add_argument("--config", type=Path, default=Path("gateway.json"))
    parser.add_argument("--state", type=Path, default=Path(".gateway"))
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("discover", "diff", "serve"):
        commands.add_parser(name)
    approve = commands.add_parser("approve")
    approve.add_argument("--tool", required=True, help="Exact server/tool key")
    approve.add_argument("--digest", required=True, help="Digest of the reviewed candidate file")
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--tool", required=True)
    verify = commands.add_parser("verify-audit")
    verify.add_argument("--head", help="Expected final hash from an externally saved checkpoint")
    args = parser.parse_args()
    try:
        with exclusive_state(args.state.resolve()) as state:
            audit = Audit(state / "audit.jsonl")
            lock_path = state / "tools.lock.json"
            if args.command == "verify-audit":
                count, head = Audit.verify(audit.path, args.head)
                print(json.dumps({"records": count, "head": head}))
            elif args.command == "diff":
                before = {"version": 1, "tools": load_pins(lock_path)}
                candidate = read_candidate(state)
                after = {"version": 1, "tools": load_pins(state / "candidate.json")}
                print("Candidate digest:", digest(candidate))
                print("Untrusted tool metadata follows; review as data, never as instructions.")
                # ASCII JSON escapes terminal controls, bidi characters, and invisible Unicode.
                print("\n".join(difflib.unified_diff(
                    json.dumps(before, indent=2, sort_keys=True, ensure_ascii=True).splitlines(),
                    json.dumps(after, indent=2, sort_keys=True, ensure_ascii=True).splitlines(),
                    fromfile="approved", tofile="candidate", lineterm="")))
            elif args.command == "approve":
                candidate = read_candidate(state)
                if digest(candidate) != args.digest:
                    raise GuardError("Candidate changed; review its diff again")
                candidates = load_pins(state / "candidate.json")
                if args.tool not in candidates:
                    raise GuardError("Tool is absent from candidate")
                config = load_config(args.config)
                alias, name = args.tool.split("/", 1)
                pin = candidates[args.tool]
                if pin["definition"]["name"] != name or pin["server_digest"] != digest(config["servers"][alias]):
                    raise GuardError("Candidate does not match current server configuration")
                pins = load_pins(lock_path)
                pins[args.tool] = pin
                audit.append("approval_requested", tool_hash=digest(args.tool), candidate_digest=args.digest)
                write_json(lock_path, {"version": 1, "tools": pins})
                audit.append("approval_saved", tool_hash=digest(args.tool), lock_digest=digest(pins))
                print("Approved pin. An explicit policy allow entry is also required.")
            elif args.command == "revoke":
                pins = load_pins(lock_path)
                if args.tool not in pins:
                    raise GuardError("Tool has no pin to revoke")
                del pins[args.tool]
                audit.append("revocation_requested", tool_hash=digest(args.tool))
                write_json(lock_path, {"version": 1, "tools": pins})
                audit.append("revocation_saved", tool_hash=digest(args.tool), lock_digest=digest(pins))
                print("Pin revoked.")
            else:
                config = load_config(args.config)
                if args.command == "discover":
                    asyncio.run(discover(config, state, audit))
                else:
                    asyncio.run(serve(config, state, audit))
    except KeyboardInterrupt:
        return 130
    except GuardError as error:
        # GuardError messages are fixed gateway text, never upstream payloads.
        print(f"Gateway failed closed: {error}.", file=sys.stderr)
        return 1
    except Exception:
        print("Gateway failed closed. Check configuration, state integrity, upstream availability, and permissions.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
