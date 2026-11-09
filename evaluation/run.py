"""Reproducible policy evaluation; no LLM, real credentials, or attack execution."""

import argparse
import copy
import json
from pathlib import Path

from mcp_gateway.security import GuardError, check_pin


def evaluate(cases):
    rows = []
    counts = {"true_positive": 0, "false_negative": 0, "false_positive": 0, "true_negative": 0}
    for case in cases:
        baseline = {"name": "add", "description": "Add two numbers.", "inputSchema": {"type": "object"}}
        current = copy.deepcopy(baseline)
        current[case["field"]] = case["value"]
        if case["state"] == "approved":
            baseline = copy.deepcopy(current)
        pins = {} if case["state"] == "new" else {"demo/add": {"definition": baseline, "server_digest": "demo"}}
        try:
            check_pin("demo/add", current, "demo", pins, {"allow": ["demo/add"], "deny": []})
            blocked = False
        except GuardError:
            blocked = True
        expected = case["state"] != "approved"
        assert blocked == expected, f"Policy regression: {case['id']}"
        category = ("true_positive" if blocked else "false_negative") if case["poisoned"] else ("false_positive" if blocked else "true_negative")
        counts[category] += 1
        rows.append({"id": case["id"], "poisoned": case["poisoned"], "state": case["state"], "blocked": blocked,
                     "expected_policy_block": expected})
    tp, fn, fp, tn = (counts[key] for key in ("true_positive", "false_negative", "false_positive", "true_negative"))
    return {
        "method": "Scenario blocking, not semantic poisoning classification or agent attack-success measurement",
        "fixture_provenance": "Original attack-inspired paraphrases plus harmless controls, not verbatim published payloads",
        "case_count": len(rows), "confusion_matrix_if_block_means_detected": counts,
        "poisoned_scenario_block_rate": tp / (tp + fn) if tp + fn else None,
        "benign_scenario_block_rate": fp / (fp + tn) if fp + tn else None,
        "policy_expectations_passed": sum(row["blocked"] == row["expected_policy_block"] for row in rows),
        "limitations": ["Small authored suite, not a representative benchmark", "Approved poisoned definitions pass",
                        "New or changed benign tools are intentionally blocked", "No LLM attack success evaluated"],
        "cases": rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    cases = json.loads(Path(__file__).with_name("cases.json").read_text(encoding="utf-8"))
    report = evaluate(cases)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
