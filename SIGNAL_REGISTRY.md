# Signal Registry — dp-scan v1.0.0

Complete reference for all 20 OWASP signals and 58 sub-checks used by dp-scan.

> **Note**: This file is for human reference and contributor documentation only.  
> The skill (`skills/scan/SKILL.md`) is fully self-contained and does not load this file at runtime.

---

## Scoring model

| Field | Description |
|---|---|
| Score | Raw sub-check weight (0–100). Higher = more critical if fired. |
| Confidence tier | `deterministic` = grep-matched, always correct; `high` = grep + context; `medium` = semantic; `low` = heuristic; `skeletal` = indicative only |
| Signal raw score | `max(fired_scores) × 0.6 + mean(other_fired_scores) × 0.4` |
| Composite | Same formula applied across fired signals |
| Amplifier | Attack chain multiplier, up to ×1.35 |

### Risk bands

| Band | Composite score |
|---|---|
| CRITICAL | ≥ 85 |
| HIGH | 60 – 84 |
| MEDIUM | 35 – 59 |
| LOW | 15 – 34 |
| CLEAN | 0 – 14 |

---

## OWASP LLM Top 10 (2025)

### OW-LLM01 — Prompt Injection

Attacker manipulates LLM behavior by injecting instructions through user-controlled input.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM01-SC01 | User input directly interpolated in prompt | 85 | deterministic | Grep: f-string / format() with user variable |
| LLM01-SC02 | Prompt passed as single string (no role separation) | 80 | deterministic | Grep: string prompt to .invoke / .run |
| LLM01-SC03 | No input validation before LLM call | 70 | high | Semantic: check for validate/sanitize before invoke |
| LLM01-SC04 | Tool description built from user string | 75 | high | Grep: Tool(name=...f"...{user...") |

---

### OW-LLM02 — Sensitive Information Disclosure

LLM inadvertently exposes private data through outputs, logs, or prompt construction.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM02-SC01 | Hardcoded API key or credential in source | 85 | deterministic | Grep: key/token = "..." with 16+ char value |
| LLM02-SC02 | PII patterns in prompt context | 75 | high | Grep: ssn / credit_card / dob = ... |
| LLM02-SC03 | LLM responses logged verbatim | 70 | deterministic | Grep: print/logger(response/content) |
| LLM02-SC04 | LLM output returned without output filtering | 60 | medium | Semantic: check for output filter before return |

---

### OW-LLM03 — Supply Chain Vulnerabilities

Compromised model, dataset, plugin, or third-party dependency injected into AI pipeline.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM03-SC01 | Unpinned or aliased model version | 65 | deterministic | Grep: model="gpt-4" (no date suffix) |
| LLM03-SC02 | Dangerous deserialization enabled | 75 | deterministic | Grep: allow_dangerous_deserialization=True |
| LLM03-SC03 | Tool/plugin loaded from arbitrary URL | 70 | high | Grep: load_tools(...url) / PluginTool(url=...) |

---

### OW-LLM04 — Data and Model Poisoning

Training data, RAG corpus, or fine-tuning dataset manipulated by attacker.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM04-SC01 | External data fed to RAG without sanitization | 70 | high | Grep: add_documents() / vectorstore.add near user input |
| LLM04-SC02 | Training data source is user-controllable | 60 | medium | Semantic: check ingestion pipeline for validation |

---

### OW-LLM05 — Insecure Output Handling

LLM output treated as trusted and used in downstream operations without sanitization.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM05-SC01 | LLM output passed to eval() or exec() | 95 | deterministic | Grep: eval/exec(response/content) |
| LLM05-SC02 | LLM output interpolated in SQL query | 90 | deterministic | Grep: cursor.execute(f"...{response...") |
| LLM05-SC03 | LLM output rendered as raw HTML | 85 | deterministic | Grep: innerHTML = response / dangerouslySetInnerHTML |
| LLM05-SC04 | LLM output used in shell command | 80 | deterministic | Grep: os.system(response) / subprocess.run(response) |

---

### OW-LLM06 — Excessive Agency

LLM given too much autonomy, capability, or permission without appropriate human oversight.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM06-SC01 | Destructive tools execute without human gate | 80 | deterministic | Grep: @tool(write/delete/send) + semantic: no confirmation |
| LLM06-SC02 | Unrestricted file system access | 75 | high | Grep: open(user_input) / Path(user_input) |
| LLM06-SC03 | No rate limiting on agent tool calls | 70 | medium | Semantic: check for throttle/rate limit in tool loop |
| LLM06-SC04 | No max_iterations / recursion_limit | 85 | deterministic | Grep: AgentExecutor() without max_iterations |

---

### OW-LLM07 — System Prompt Leakage

System prompt (containing instructions, persona, or confidential config) exposed to users.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM07-SC01 | System prompt in plaintext accessible file | 70 | high | Grep: open("...system_prompt...") |
| LLM07-SC02 | No check for system prompt echoing in output | 65 | medium | Semantic: look for output post-processing to strip prompt |

---

### OW-LLM08 — Vector and Embedding Weaknesses

Vector store queries or embeddings manipulated to return malicious or attacker-controlled content.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM08-SC01 | Raw user query passed to vector store | 70 | high | Grep: similarity_search(user_input/query) |
| LLM08-SC02 | Retrieved docs not filtered before LLM context | 55 | medium | Semantic: check RAG chain for doc filtering step |

---

### OW-LLM09 — Misinformation

LLM generates false, misleading, or hallucinated content presented as fact.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM09-SC01 | Temperature > 0.7 in agent context | 55 | deterministic | Grep: temperature=0.8 / 0.9 / 1.0+ |
| LLM09-SC02 | No grounding/RAG for factual domains | 45 | low | Semantic: agent handles factual domain with no retriever |

---

### OW-LLM10 — Unbounded Consumption

LLM or agent consumes excessive resources (tokens, API calls, cost) without limits.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| LLM10-SC01 | max_tokens not set on LLM call | 75 | deterministic | Grep: ChatOpenAI/ChatAnthropic() without max_tokens |
| LLM10-SC02 | Async LLM calls without timeout | 70 | high | Grep: await .ainvoke() without asyncio.wait_for |
| LLM10-SC03 | Recursive agent without depth guard | 80 | deterministic | Grep: agent calling self / recursion_limit absent |
| LLM10-SC04 | No token counting or cost monitoring | 55 | medium | Semantic: no get_openai_callback() or usage tracking |

---

## OWASP ASI Top 10 — Agentic Security Initiative (2026)

### OW-ASI01 — Goal Hijacking

Attacker manipulates agent's goal or objective through prompt or environment manipulation.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI01-SC01 | Goal set from user input without validation | 80 | high | Grep: goal/objective = user_input/request |
| ASI01-SC02 | No goal boundary or scope constraint | 75 | medium | Semantic: no allowlist or constraint on agent goal |

---

### OW-ASI02 — Tool Misuse / Privilege Abuse

Agent uses tools beyond intended scope or in ways that cause harm.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI02-SC01 | Shell/exec tools in production tool list | 90 | deterministic | Grep: ShellTool / BashTool / PythonREPLTool |
| ASI02-SC02 | Tools lack authorization checks | 75 | high | Grep: @tool def + semantic: no auth check |
| ASI02-SC03 | Tool output drives privileged op without validation | 80 | high | Semantic: tool1_output → tool2_input without parsing |

---

### OW-ASI03 — Inter-Agent Trust Exploitation

Compromised sub-agent sends malicious instructions to orchestrator or other agents.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI03-SC01 | No authentication between agents | 75 | high | Grep: multi-agent calls without auth token/HMAC |
| ASI03-SC02 | Input from other agents not schema-validated | 70 | medium | Semantic: Pydantic/TypedDict absent on agent message receipt |

---

### OW-ASI04 — Human-in-the-Loop Bypass

Agent executes high-impact operations without human review or approval.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI04-SC01 | High-impact tools with no approval step | 85 | deterministic | Grep: @tool(delete/send/deploy) + semantic: no confirm |
| ASI04-SC02 | LangGraph compiled without interrupt_before | 75 | deterministic | Grep: .compile() without interrupt_before=[...] |

---

### OW-ASI05 — Resource Overuse

Agent consumes excessive compute, memory, API calls, or storage.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI05-SC01 | Unbounded parallel tool calls | 75 | deterministic | Grep: asyncio.gather(*...) without semaphore |
| ASI05-SC02 | Memory grows without pruning | 65 | medium | Grep: ConversationBufferMemory() without max_token_limit |

---

### OW-ASI06 — Data Exfiltration via Agent

Agent used as exfiltration channel, leaking sensitive data to external systems.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI06-SC01 | Sensitive data passed to external HTTP tool | 80 | high | Grep: requests.post(...password/token/secret) |
| ASI06-SC02 | Agent calls arbitrary external URLs | 65 | medium | Grep: requests.get(user_input/query) |

---

### OW-ASI07 — Rogue Behaviour

Agent acts outside its intended purpose, potentially self-modifying or taking unauthorized actions.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI07-SC01 | Agent can overwrite its own instructions | 80 | high | Grep: open("system_prompt","w") / self.system_prompt = response |
| ASI07-SC02 | No structured audit logging of agent actions | 75 | deterministic | Inverse grep: no import logging anywhere → fires |

---

### OW-ASI08 — Privilege Escalation

Agent gains permissions beyond its intended role.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI08-SC01 | Agent has permission-granting tools | 75 | high | Grep: @tool(grant/escalate/set_role) |
| ASI08-SC02 | LLM-generated credentials used for auth | 70 | high | Grep: auth(response.content) / token = response |

---

### OW-ASI09 — Critical Decision Without Validation

Agent makes high-stakes decisions based purely on LLM output without human or programmatic validation.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI09-SC01 | No try/except around LLM invocations | 75 | deterministic | Grep: .invoke() not wrapped in try/except |
| ASI09-SC02 | LLM output drives critical operation directly | 70 | high | Grep: payment/diagnosis/deploy ... response |

---

### OW-ASI10 — Cascading Failures

Failure in one agent component propagates and amplifies through the system.

| Sub-check ID | Label | Score | Confidence | Method |
|---|---|---|---|---|
| ASI10-SC01 | Exceptions not contained in tool functions | 60 | medium | Grep: bare raise / unhandled exception in tool |
| ASI10-SC02 | No retry limit or circuit breaker | 55 | medium | Inverse grep: no tenacity/backoff/retry anywhere |

---

## Attack Chains

Cross-signal combinations that indicate compound attack vectors. Each fired chain applies a score amplifier.

| Chain ID | Required Sub-checks | Amplifier | Description |
|---|---|---|---|
| RCE-via-agent | LLM05-SC01 + ASI02-SC01 | ×1.35 | Remote code execution: eval(LLM output) + unrestricted shell |
| prompt-to-exfil | LLM01-SC01 + ASI06-SC01 | ×1.30 | Prompt injection enables data extraction via external tool |
| unbounded-execution | LLM06-SC04 + ASI05-SC01 + LLM10-SC03 | ×1.25 | No iteration limit + unbounded parallel + recursive loops |
| supply-chain-priv-esc | LLM03-SC03 + ASI08-SC01 | ×1.20 | Untrusted plugin combined with privilege-granting tool |
| hitl-bypass | ASI04-SC01 + LLM06-SC01 | ×1.15 | High-impact tools + no human approval = full autonomous operation |
