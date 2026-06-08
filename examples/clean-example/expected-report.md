# Expected dp-scan Report — clean-example

```
COMPOSITE RISK SCORE: 8 / 100   BAND: CLEAN
Frameworks detected: LangGraph, Anthropic SDK
Attack chains detected: none
Sub-checks fired: 1 / 58   Signals triggered: 1 / 20
```

## Expected fired signals

| Signal | Status | Notes |
|---|---|---|
| OW-LLM09 | FIRED (low) | SC02 — no explicit RAG retriever (semantic/skeletal check, score 45) |
| All other signals | CLEAN ✓ | |

## Why this is clean

| Security concern | Mitigation in code |
|---|---|
| Prompt injection | `ChatPromptTemplate.from_messages` — user input in `{user_message}` slot only |
| Hardcoded secrets | `os.environ["ANTHROPIC_API_KEY"]` — crashes on missing, never hardcoded |
| max_tokens | `max_tokens=MAX_RESPONSE_TOKENS` always set |
| Model pinning | `claude-opus-4-8-20251101` — specific version pinned |
| eval/exec | Never used — `PydanticOutputParser` for structured output |
| Shell tools | Not present — only `read_document` and `search_internal_api` |
| Path traversal | `pathlib.Path.resolve()` + allowlist check |
| Arbitrary URLs | Domain allowlist — only `api.internal.company.com` |
| No max iterations | `AGENT_MAX_ITERATIONS = 10` + `recursion_limit=AGENT_MAX_ITERATIONS` |
| No timeout | `asyncio.wait_for(..., timeout=30.0)` on every LLM call |
| No retry limit | `tenacity.stop_after_attempt(3)` with exponential backoff |
| Human-in-the-loop | `interrupt_before=["agent"]` on graph.compile() |
| No audit trail | `structlog` logging of every tool call, user ID, outcome |
| No input validation | `UserRequest(BaseModel)` with validators — rejects injection patterns |
| No error handling | Every LLM call in try/except, fallback output returned |
| No auth on tools | `@require_auth` decorator on all tools |
| Unbounded memory | LangGraph checkpointer — bounded by session, not unbounded buffer |
