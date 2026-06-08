# Expected dp-scan Report — vulnerable-anthropic

```
COMPOSITE RISK SCORE: 92 / 100   BAND: CRITICAL
Frameworks detected: Anthropic SDK
Attack chains detected: RCE-via-agent (×1.35), hitl-bypass (×1.15)
Sub-checks fired: 12 / 58   Signals triggered: 8 / 20
```

## Expected fired signals

| Signal | Key sub-checks |
|---|---|
| OW-LLM01 | SC01 (f-string with user_input in build_prompt) |
| OW-LLM02 | SC01 (hardcoded sk-ant- key), SC03 (print(response)) |
| OW-LLM03 | SC01 (claude-3-opus unpinned) |
| OW-LLM05 | SC01 (exec(tool_input["code"])), SC02 (SQL f-string injection) |
| OW-LLM06 | SC01 (delete_records no confirmation) |
| OW-LLM10 | SC01 (messages.create without max_tokens × 2 calls) |
| OW-ASI04 | SC01 (delete_records executes without human approval) |
| OW-ASI09 | SC01 (no try/except), SC02 (stripe.Charge from LLM output) |
