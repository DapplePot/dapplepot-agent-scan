# Expected dp-scan Report — vulnerable-langchain

Running `/dp-scan` in this directory should produce approximately:

```
COMPOSITE RISK SCORE: 97 / 100   BAND: CRITICAL
Frameworks detected: LangChain
Attack chains detected: RCE-via-agent (×1.35), hitl-bypass (×1.15)
Sub-checks fired: 18 / 58   Signals triggered: 10 / 20
```

## Expected fired signals

| Signal | Status | Expected score | Key sub-checks |
|---|---|---|---|
| OW-LLM01 | FIRED | 82 | SC01 (f-string prompt), SC03 (no validation) |
| OW-LLM02 | FIRED | 85 | SC01 (hardcoded API key), SC03 (verbose logging) |
| OW-LLM03 | FIRED | 74 | SC01 (gpt-4 alias), SC02 (dangerous deserialization) |
| OW-LLM05 | FIRED | 95 | SC01 (eval), SC02 (SQL injection), SC04 (shell) |
| OW-LLM06 | FIRED | 85 | SC01 (no confirm), SC02 (no path validation), SC04 (no max_iterations) |
| OW-LLM08 | FIRED | 70 | SC01 (raw vector query) |
| OW-LLM09 | FIRED | 55 | SC01 (temperature=0.9) |
| OW-LLM10 | FIRED | 75 | SC01 (no max_tokens) |
| OW-ASI02 | FIRED | 90 | SC01 (ShellTool equivalent) |
| OW-ASI04 | FIRED | 85 | SC01 (write_to_file no confirmation) |
| OW-ASI07 | FIRED | 80 | SC01 (overwrites system_prompt.txt) |

## Lines that should be flagged

| Line | Sub-check | Reason |
|---|---|---|
| 16 | LLM02-SC01 | Hardcoded `sk-proj-abc123...` API key |
| 20 | LLM10-SC01 | `ChatOpenAI()` without `max_tokens` |
| 21 | LLM03-SC01 | `model="gpt-4"` (unpinned alias) |
| 22 | LLM09-SC01 | `temperature=0.9` |
| 26 | ASI05-SC02 | `ConversationBufferMemory()` with no limit |
| 30 | LLM03-SC02 | `allow_dangerous_deserialization=True` |
| 36 | LLM05-SC01 | `eval(code)` |
| 43 | ASI02-SC01 | `subprocess.run(command, shell=True)` |
| 50 | LLM06-SC01 | `write_to_file` with no confirmation |
| 50 | LLM06-SC02 | `open(filename, "w")` with no path validation |
| 61 | LLM05-SC02 | `cursor.execute(f"...'{query}'")` — SQL injection |
| 70 | LLM08-SC01 | `vectorstore.similarity_search(query)` |
| 88 | LLM01-SC01 | `f"...{user_input}..."` in prompt |
| 88 | LLM01-SC03 | No validation before `agent.invoke()` |
| 88 | ASI09-SC01 | No try/except around `agent.invoke()` |
| 91 | LLM02-SC03 | `print(f"Agent response: {result['output']}")` |
| 96 | ASI07-SC01 | `open("system_prompt.txt", "w")` with LLM content |
