# Expected dp-scan Report — vulnerable-openai

```
COMPOSITE RISK SCORE: 94 / 100   BAND: CRITICAL
Frameworks detected: OpenAI SDK
Attack chains detected: RCE-via-agent (×1.35), hitl-bypass (×1.15)
Sub-checks fired: 14 / 58   Signals triggered: 9 / 20
```

## Expected fired signals

| Signal | Status | Key sub-checks |
|---|---|---|
| OW-LLM01 | FIRED | SC01 (string concatenation in messages), SC03 (no validation) |
| OW-LLM02 | FIRED | SC01 (hardcoded sk- key), SC03 (verbose print of tool results) |
| OW-LLM03 | FIRED | SC01 (gpt-4 alias) |
| OW-LLM05 | FIRED | SC01 (eval in execute_python) |
| OW-LLM06 | FIRED | SC01 (send_email no confirmation), SC03 (no rate limit on tool loop) |
| OW-LLM07 | FIRED | SC01 (open("system_prompt.txt")) |
| OW-LLM10 | FIRED | SC01 (no max_completion_tokens), SC02 (asyncio.gather without timeout) |
| OW-ASI04 | FIRED | SC01 (send_email executes without approval) |
| OW-ASI05 | FIRED | SC01 (asyncio.gather(*[...]) without semaphore) |
