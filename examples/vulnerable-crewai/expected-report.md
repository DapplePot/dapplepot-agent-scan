# Expected dp-scan Report — vulnerable-crewai

```
COMPOSITE RISK SCORE: 88 / 100   BAND: CRITICAL
Frameworks detected: CrewAI, LangChain (via ChatOpenAI)
Attack chains detected: RCE-via-agent (×1.35), hitl-bypass (×1.15)
Sub-checks fired: 13 / 58   Signals triggered: 9 / 20
```

## Expected fired signals

| Signal | Key sub-checks |
|---|---|
| OW-LLM01 | SC01 (f-string with user_request in task description) |
| OW-LLM02 | SC01 (hardcoded sk- key), SC03 (print verbose) |
| OW-LLM03 | SC01 (gpt-4 alias) |
| OW-LLM05 | SC01 (eval in execute_code_tool) |
| OW-LLM06 | SC01 (deploy no confirmation), SC04 (max_iter absent on both agents) |
| OW-LLM09 | SC01 (temperature=0.8) |
| OW-ASI01 | SC01 (goal from user_request), SC02 (allow_delegation=True no scope) |
| OW-ASI04 | SC01 (deploy_application_tool no human approval) |
| OW-ASI06 | SC02 (requests.get(url) from agent) |
