# Research and evaluation

[Project README](../README.md) | [Machine-readable results](../evaluation/results.json) | [Fixtures](../evaluation/cases.json)

## Sources checked on November 8, 2026

- [Uber: Designing MCP Gateway](https://www.uber.com/us/en/blog/designing-mcp-gateway/) describes centralized tool management, owner-reviewed description changes, per-tool authorization, and response redaction. It motivates the approval workflow; this local project does not reproduce Uber's platform or scale.
- [Invariant Labs: MCP Security Notification](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) describes instruction-bearing tool definitions, credential theft, concealment, and cross-tool influence. Fixtures paraphrase those patterns as inert strings.
- [MCP Tool Poisoning in Agentic AI Frameworks](https://arxiv.org/abs/2611.03555) examines tool descriptions, schema fields, and response data. It motivates schema-field fixtures and the distinction between a metadata check and observed attack execution.
- [Datadog: N4D Mesh Controller](https://securitylabs.datadoghq.com/articles/n4d-mesh-controller-go-titan-new-infrastructure-hunting/) documents automated enumeration and invocation of dangerous capabilities on exposed MCP servers. That is a distinct exposure/authorization problem, not evidence that pinning detects poisoned prose. No malware or live infrastructure from that article is used here.
- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) supplies the transport implementation. This project pins SDK version 1.27.0.

## Method

`python -m evaluation.run --output evaluation/results.json` exercises the same `check_pin` function used by the gateway. Fifteen fixtures vary the content label (poisoned/harmless) and trust state (new/changed/approved). Each attack-inspired case records its source and adaptation. The payloads are original paraphrases, not verbatim published attack samples or a licensed research dataset. No payload is executed.

The experiment asks whether definitions are blocked. It does not ask an LLM to follow instructions, measure successful exfiltration, or run a semantic detector. Every case also asserts the expected pinning-policy decision, so a policy regression fails the run.

## Recorded results

| Scenario group | Blocked | Total |
| --- | ---: | ---: |
| Poisoned new or changed definitions | 5 | 5 |
| Poisoned definitions already approved by the operator | 0 | 2 |
| Harmless approved definitions | 0 | 5 |
| Harmless new or changed definitions | 3 | 3 |
| Correct policy decisions | 15 | 15 |

If someone labels every block as a poisoning detection, the confusion matrix is TP=5, FN=2, FP=3, TN=5. That yields a 71.4% true-positive rate and a 37.5% false-positive rate **on this authored scenario mix only**. The three benign blocks are intentional review requirements, and both misses are intentionally approved poisoned baselines. Changing the mix of approval states changes these numbers without changing the gateway.

These figures therefore describe scenario blocking and review burden, not general poisoning-classifier accuracy. Do not report only the 5/5 mutated-attack result as "100% tool poisoning detection." he suite is small, authored alongside the implementation, and not independent or representative. There is no measured redaction recall across real secret/PII formats and no agent attack-success rate.

