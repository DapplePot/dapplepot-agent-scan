# DapplePot Agent Security Scan — dp-scan

**Version:** 1.0.0  
**Frameworks covered:** LangChain · LangGraph · OpenAI SDK · Anthropic SDK · Google ADK · CrewAI  
**Standards:** OWASP LLM Top 10 (2025) · OWASP Agentic Security Initiative (ASI) Top 10 (2026)  
**Model:** OWASP signals × sub-checks — 20 signals, 58 sub-checks, attack chain amplification

---

You are performing a security audit of an AI agent codebase. Follow every phase in order. Do not skip phases. Be precise and thorough.

---

## PHASE 0 — SETUP

Ask the user two questions (prompt interactively; if non-interactive or no response, use defaults):

1. **Scan path** (default: current working directory)  
   > "What directory should I scan? Leave blank for current directory."

2. **Report format** (default: terminal markdown)  
   > Options: terminal markdown / HTML file (dp-scan-report.html) / JSON file (dp-scan-report.json) / all three

Store answers. If blank for path, use `.` (current directory). If no input received (non-interactive), default to terminal markdown.

---

## PHASE 1 — FRAMEWORK DETECTION

Run these Grep searches in the scan path. Mark each framework as **detected** or **not detected**.

```
LANGCHAIN:   grep pattern "from langchain|import langchain"       → files with matches
LANGGRAPH:   grep pattern "from langgraph|import langgraph"       → files with matches
OPENAI:      grep pattern "from openai|import openai|OpenAI\("    → files with matches
ANTHROPIC:   grep pattern "from anthropic|import anthropic"       → files with matches
GOOGLE_ADK:  grep pattern "from google\.adk|from google\.genai|google-adk|generativeai" → files with matches
CREWAI:      grep pattern "from crewai|import crewai"             → files with matches
```

If zero frameworks detected: output "No AI agent framework imports found. Nothing to scan." and stop.

List detected frameworks. Note the file count for each. Continue with all detected frameworks' specific checks in Phase 3.

---

## PHASE 2 — FILE INVENTORY

Glob for all Python and JavaScript/TypeScript source files in the scan path (exclude node_modules, .venv, venv, __pycache__, .git, dist, build):

```
Glob: **/*.py          (exclude: **/node_modules/**, **/.venv/**, **/venv/**, **/__pycache__/**)
Glob: **/*.{js,ts,jsx,tsx}   (exclude: **/node_modules/**, **/dist/**)
```

Count total files. You will grep within these files for all sub-checks.

---

## PHASE 3 — STATIC SUB-CHECK ANALYSIS

For each sub-check below, run the specified Grep. Record every match with: file path, line number, matched line content (3 lines of context). A sub-check **fires** if at least one match is found.

Work through all 58 sub-checks. Keep a running table of results.

---

### SIGNAL: OW-LLM01 — Prompt Injection

**LLM01-SC01** | Score: 85 | Confidence: deterministic  
Label: User-controlled input directly interpolated into prompt string  
```
Grep: f"[^"]*\{(user_input|user_message|user_query|human_input|query|message|prompt|user_text|request)[^}]*\}
Also: \+\s*(user_input|user_message|user_query|query|message|prompt)
Also: format\(.*?(user_input|user_message|query|message|prompt)
Also: template\.format.*?(user_input|message|query)
```
Fire if any match found in or near LLM invocation context.

**LLM01-SC02** | Score: 80 | Confidence: deterministic  
Label: Prompt passed as single string (no message role separation)  
```
Grep: \.invoke\(\s*["'][^"']*\{
Also: llm\.predict\(\s*[^{]
Also: chain\.run\(\s*["']
Also: completion\s*=\s*client\.(complete|chat)\([^)]*prompt\s*=\s*[^,)]*\+
```
Note: This checks for string-only prompts being passed without system/user role separation.

**LLM01-SC03** | Score: 70 | Confidence: high  
Label: No input validation or sanitization before LLM call  
Semantic check — see Phase 4.

**LLM01-SC04** | Score: 75 | Confidence: high  
Label: Tool name or description built from user-provided string  
```
Grep: Tool\(.*name\s*=.*\+|Tool\(.*name\s*=.*f"
Also: @tool.*def.*\(.*user|description\s*=.*f".*\{(user|query|input)
```

---

### SIGNAL: OW-LLM02 — Sensitive Information Disclosure

**LLM02-SC01** | Score: 85 | Confidence: deterministic  
Label: Hardcoded API key, secret, or credential in source  
```
Grep: (api_key|apikey|secret_key|password|token|auth_token)\s*=\s*["'][A-Za-z0-9_\-]{16,}["']
Also: sk-[A-Za-z0-9]{32,}
Also: sk-ant-[A-Za-z0-9\-_]{32,}
Also: AIza[A-Za-z0-9\-_]{32,}
```

**LLM02-SC02** | Score: 75 | Confidence: high  
Label: PII or sensitive data patterns included in prompt context  
```
Grep: (ssn|social_security|credit_card|card_number|cvv|dob|date_of_birth)\s*=
Also: \b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b
Also: (email|phone|address)\s*=.*context|system_prompt
```

**LLM02-SC03** | Score: 70 | Confidence: deterministic  
Label: LLM responses logged verbatim without filtering  
```
Grep: (print|logger\.(info|debug|warning)|logging\.(info|debug))\s*\(.*\b(response|result|output|completion|content)\b
Also: console\.(log|info|debug)\s*\(.*\b(response|result|output)\b
```

**LLM02-SC04** | Score: 60 | Confidence: medium  
Label: LLM output returned to user without output filtering  
Semantic check — see Phase 4.

---

### SIGNAL: OW-LLM03 — Supply Chain Vulnerabilities

**LLM03-SC01** | Score: 65 | Confidence: deterministic  
Label: Unpinned or alias model version (no specific version pin)  
```
Grep: model\s*=\s*["'](gpt-4|gpt-4o|gpt-3\.5-turbo|gemini-pro|llama-2)["']
Also: model\s*=\s*["'](claude-3-opus|claude-3-sonnet|claude-3-haiku|claude-3-5-sonnet|claude-opus-4|claude-sonnet-4)["']
Also: model_name\s*=\s*["'](gpt-4|gpt-3\.5-turbo)["']
```
Note: These are version aliases that may change. Pinned versions include a date suffix, e.g. "gpt-4-0613" or "claude-opus-4-8-20251101". Be careful not to flag `claude-3-opus-20240229` — it has a date suffix and is pinned.

**LLM03-SC02** | Score: 75 | Confidence: deterministic  
Label: Dangerous deserialization enabled  
```
Grep: allow_dangerous_deserialization\s*=\s*True
Also: pickle\.loads\(
Also: yaml\.load\([^,)]*\)(?!\s*,\s*Loader)
Also: allow_dangerous_code\s*=\s*True
```

**LLM03-SC03** | Score: 70 | Confidence: high  
Label: Plugin or tool loaded from arbitrary URL or untrusted source  
```
Grep: load_tools\(.*url|PluginTool\(.*url|requests\.get.*tool|load_from_url
Also: Tool\.from_function\(.*requests\.get
Also: plugin.*=.*requests\.(get|post)
```

---

### SIGNAL: OW-LLM04 — Data and Model Poisoning

**LLM04-SC01** | Score: 70 | Confidence: high  
Label: External/user-provided data fed to RAG corpus without sanitization  
```
Grep: add_documents\(|add_texts\(|from_documents\(|vectorstore\.add
Also: fine_tune.*=.*user|fine_tuning.*dataset.*user
```
Note: Fires if found — semantic check needed to confirm lack of sanitization.

**LLM04-SC02** | Score: 60 | Confidence: medium  
Label: Training or embedding data source is user-controllable  
Semantic check — see Phase 4.

---

### SIGNAL: OW-LLM05 — Insecure Output Handling

**LLM05-SC01** | Score: 95 | Confidence: deterministic  
Label: LLM output executed as code (eval/exec)  
```
Grep: eval\s*\(.*\b(response|result|output|content|text|completion)\b
Also: exec\s*\(.*\b(response|result|output|content|text|completion)\b
Also: eval\s*\(.*\.content\b
Also: exec\s*\(.*\.content\b
```

**LLM05-SC02** | Score: 90 | Confidence: deterministic  
Label: LLM output interpolated into SQL query  
```
Grep: (cursor\.execute|session\.execute|db\.execute)\s*\(.*f".*\{
Also: execute\s*\(.*\+.*\b(response|output|content|result)\b
Also: execute\s*\(.*\b(response|output|content|result)\b.*\+
Also: SELECT.*\+.*response|INSERT.*\+.*response|UPDATE.*\+.*response
```

**LLM05-SC03** | Score: 85 | Confidence: deterministic  
Label: LLM output rendered as raw HTML (XSS risk)  
```
Grep: innerHTML\s*=.*\b(response|output|content|result)\b
Also: dangerouslySetInnerHTML.*\b(response|output|content|result)\b
Also: document\.write\s*\(.*\b(response|output|content)\b
Also: render_template_string\s*\(.*\b(response|output|content)\b
```

**LLM05-SC04** | Score: 80 | Confidence: deterministic  
Label: LLM output used in shell command  
```
Grep: os\.system\s*\(.*\b(response|output|content|result)\b
Also: subprocess\.(run|Popen|call)\s*\(.*\b(response|output|content|result)\b
Also: subprocess\.(run|Popen)\s*\(.*shell\s*=\s*True
Also: os\.popen\s*\(.*\b(response|output|content)\b
```

---

### SIGNAL: OW-LLM06 — Excessive Agency

**LLM06-SC01** | Score: 80 | Confidence: deterministic  
Label: File write/delete/send tools execute without human confirmation gate  
```
Grep: def.*write.*file|def.*delete.*file|def.*send.*email|def.*send.*message
Also: @tool.*def.*(write|delete|send|modify|update|create)
Also: return_direct\s*=\s*True
```
Note: Check if any of these tools have a confirmation step or interrupt before them.

**LLM06-SC02** | Score: 75 | Confidence: high  
Label: Unrestricted file system access (no path validation)  
```
Grep: open\s*\(.*user_input|open\s*\(.*query|open\s*\(.*f".*\{
Also: Path\s*\(.*user_input|os\.path\.join\s*\(.*user_input
Also: shutil\.(copy|move|rmtree)\s*\(.*user_input
```

**LLM06-SC03** | Score: 70 | Confidence: deterministic  
Label: No rate limiting on agent tool calls  
Semantic check — see Phase 4.

**LLM06-SC04** | Score: 85 | Confidence: deterministic  
Label: Agent loop has no maximum iteration limit  
```
Grep: AgentExecutor\s*\(
Also: create_react_agent\s*\(
Also: initialize_agent\s*\(
```
For each file containing these patterns: read the surrounding code block and check if `max_iterations` is set anywhere in the same AgentExecutor instantiation (which may span multiple lines). If absent → fires.

Also check LangGraph:
```
Grep: StateGraph\s*\(|CompiledGraph\s*\(
```
For each file: read the `.compile()` call and check if `recursion_limit` is NOT passed in the config dict.

---

### SIGNAL: OW-LLM07 — System Prompt Leakage

**LLM07-SC01** | Score: 70 | Confidence: high  
Label: System prompt stored in plaintext file accessible to web requests  
```
Grep: open\s*\(["'].*system.*prompt|open\s*\(["'].*instructions
Also: system_prompt\s*=\s*open\s*\(
Also: SYSTEM_PROMPT\s*=\s*"""
```

**LLM07-SC02** | Score: 65 | Confidence: medium  
Label: No check for system prompt echoing in output  
Semantic check — see Phase 4.

---

### SIGNAL: OW-LLM08 — Vector and Embedding Weaknesses

**LLM08-SC01** | Score: 70 | Confidence: high  
Label: Raw user query passed to vector store without sanitization  
```
Grep: similarity_search\s*\(.*\b(user_input|query|message|request)\b
Also: search\s*\(.*\b(user_input|query|message)\b
Also: vectorstore\.(search|query)\s*\(.*\b(user_input|query)\b
Also: retriever\.get_relevant_documents\s*\(.*\b(user_input|query|message)\b
```

**LLM08-SC02** | Score: 55 | Confidence: medium  
Label: Retrieved documents passed to LLM without content filtering  
Semantic check — see Phase 4.

---

### SIGNAL: OW-LLM09 — Misinformation

**LLM09-SC01** | Score: 55 | Confidence: deterministic  
Label: Temperature set above 0.7 for LLM in agent context  
```
Grep: temperature\s*=\s*(?:0\.[89][0-9]*|1\.[0-9]*)
Also: temperature\s*=\s*[1-9][0-9]*
```

**LLM09-SC02** | Score: 45 | Confidence: low  
Label: LLM used for factual answers with no RAG/grounding mechanism  
Semantic check — see Phase 4.

---

### SIGNAL: OW-LLM10 — Unbounded Consumption

**LLM10-SC01** | Score: 75 | Confidence: deterministic  
Label: max_tokens / max_completion_tokens not set on LLM calls  
```
Grep: ChatOpenAI\s*\(
Also: AzureChatOpenAI\s*\(
Also: ChatAnthropic\s*\(
Also: client\.chat\.completions\.create\s*\(
Also: client\.messages\.create\s*\(
```
For each file containing these patterns: read the surrounding constructor/call block (may span multiple lines) and check if `max_tokens` or `max_completion_tokens` is set. If absent → fires.

**LLM10-SC02** | Score: 70 | Confidence: high  
Label: Async LLM calls without timeout  
```
Grep: await.*\.ainvoke\s*\(
Also: await.*\.arun\s*\(
Also: await.*acomplete\s*\(
Also: asyncio\.create_task\s*\(.*invoke
```
Check if `asyncio.wait_for` or `timeout=` wraps the call. If not → fires.

**LLM10-SC03** | Score: 80 | Confidence: deterministic  
Label: Recursive agent invocation without depth/iteration guard  
```
Grep: def\s+\w+.*:\s*(?:.*\n)*.*\w+\.invoke\s*\(
Also: recursion_limit
Also: max_depth\s*=
```
Check for agent functions that call themselves or other agents recursively. If no `recursion_limit` config is found in LangGraph state configs → fires.

**LLM10-SC04** | Score: 55 | Confidence: medium  
Label: No token counting or cost budget guard  
Semantic check — see Phase 4.

---

### SIGNAL: OW-ASI01 — Goal Hijacking

**ASI01-SC01** | Score: 80 | Confidence: high  
Label: Agent goal/objective set from user-provided input without validation  
```
Grep: (goal|objective|task|mission)\s*=.*\b(user_input|request|query|message)\b
Also: Agent\s*\(.*goal\s*=.*f".*\{
Also: crew\.kickoff\s*\(.*\b(user_input|request|query)\b
```

**ASI01-SC02** | Score: 75 | Confidence: medium  
Label: No goal boundary or scope validation in agent config  
Semantic check — see Phase 4.

---

### SIGNAL: OW-ASI02 — Tool Misuse / Privilege Abuse

**ASI02-SC01** | Score: 90 | Confidence: deterministic  
Label: Shell, exec, or unrestricted REPL tools exposed in production tool list  
```
Grep: ShellTool\s*\(\|BashTool\s*\(\|PythonREPLTool\s*\(\|PythonAstREPLTool\s*\(
Also: Tool\s*\(.*shell\s*=\s*True
Also: tools\s*=\s*\[.*ShellTool
Also: tools\s*=\s*\[.*BashTool
Also: tools\s*=\s*\[.*REPL
Also: subprocess\.run.*shell\s*=\s*True(?!.*timeout)
```

**ASI02-SC02** | Score: 75 | Confidence: high  
Label: Tool functions have no authorization or permission check  
```
Grep: @tool\s*\ndef\s+\w+\s*\(
Also: class\s+\w+\s*\(\s*BaseTool\s*\)
Also: StructuredTool\.from_function\s*\(
```
For each tool definition found: check if any auth/permission validation code exists in or before the function body.

**ASI02-SC03** | Score: 80 | Confidence: high  
Label: Tool output directly drives another privileged tool without validation  
Semantic check — see Phase 4.

---

### SIGNAL: OW-ASI03 — Inter-Agent Trust Exploitation

**ASI03-SC01** | Score: 75 | Confidence: high  
Label: No authentication between agents in multi-agent setup  
```
Grep: (SubAgent|ChatOpenAI|anthropic\.messages|create_agent).*agent.*call
Also: agent\.invoke\s*\(.*agent
Also: crew\.kickoff|langgraph.*multi.*agent
Also: send_message\s*\(|communicate\s*\(
```
Check if agent-to-agent calls include any auth token, signature, or trust verification.

**ASI03-SC02** | Score: 70 | Confidence: medium  
Label: Input from other agents accepted without schema validation  
Semantic check — see Phase 4.

---

### SIGNAL: OW-ASI04 — Human-in-the-Loop Bypass

**ASI04-SC01** | Score: 85 | Confidence: deterministic  
Label: High-impact operations executed without human approval  
```
Grep: @tool.*def.*(delete|remove|drop|truncate|send_email|send_message|transfer|deploy|push|publish)
Also: def.*(delete|remove|drop|send_email|transfer)\s*\(
```
Check if these tools have any `interrupt_before`, `human_input`, `confirm`, or `approval` mechanism.

**ASI04-SC02** | Score: 75 | Confidence: deterministic  
Label: LangGraph graph compiled without interrupt_before for sensitive nodes  
```
Grep: graph\.compile\s*\(\s*\)
Also: \.compile\s*\(\s*checkpointer
Also: StateGraph\s*\(
```
For each `graph.compile()` call, check if `interrupt_before=[...]` is absent → fires.

---

### SIGNAL: OW-ASI05 — Resource Overuse

**ASI05-SC01** | Score: 75 | Confidence: deterministic  
Label: Unbounded parallel tool execution  
```
Grep: asyncio\.gather\s*\(\*
Also: ThreadPoolExecutor\s*\(\s*\)(?!\s*as\s+|\s*,\s*max_workers)
Also: asyncio\.gather\s*\(.*for.*in
Also: map\s*\(.*tool.*,.*tasks\s*\)
```
Check if `max_workers`, `semaphore`, or explicit limit is absent.

**ASI05-SC02** | Score: 65 | Confidence: medium  
Label: Conversation memory grows without pruning or token budget  
```
Grep: ConversationBufferMemory\s*\(\s*\)
Also: memory\s*=\s*\[\]
Also: messages\.append\s*\(
```
Check if `max_token_limit` or windowing is absent from memory config.

---

### SIGNAL: OW-ASI06 — Data Exfiltration via Agent

**ASI06-SC01** | Score: 80 | Confidence: high  
Label: Sensitive data passed to external HTTP tool without filtering  
```
Grep: requests\.(get|post|put)\s*\(.*\b(api_key|password|token|secret|ssn|email)\b
Also: tool.*http.*\+.*\b(user_data|personal|private|sensitive)\b
Also: aiohttp\.(get|post)\s*\(.*\b(password|token|secret)\b
```

**ASI06-SC02** | Score: 65 | Confidence: medium  
Label: No egress control — agent can call arbitrary external URLs  
```
Grep: requests\.(get|post)\s*\(.*\b(user_input|query|url)\b
Also: httpx\.(get|post)\s*\(.*\b(user_input|query)\b
Also: Tool.*url\s*=.*\b(user_input|query|message)\b
```

---

### SIGNAL: OW-ASI07 — Rogue Behaviour

**ASI07-SC01** | Score: 80 | Confidence: high  
Label: Agent can overwrite its own instructions or memory  
```
Grep: open\s*\(.*system_prompt.*['"w]|open\s*\(.*instructions.*['"w]
Also: write.*system_prompt|update.*instructions.*=
Also: memory\[["']system["']\]\s*=
Also: self\.system_prompt\s*=.*\b(response|output|content)\b
```

**ASI07-SC02** | Score: 75 | Confidence: deterministic  
Label: No structured audit logging of agent actions  
```
Grep: import logging|from logging|logger\s*=\s*logging\.getLogger
```
Fire if NO structured logging is found in tool definitions or agent execution. Inverse check: if `logging` or `structlog` is not imported anywhere → fires.

---

### SIGNAL: OW-ASI08 — Privilege Escalation

**ASI08-SC01** | Score: 75 | Confidence: high  
Label: Agent has access to permission-granting or role-modification tools  
```
Grep: def.*(grant|escalate|promote|set_role|add_permission|set_permission)
Also: @tool.*def.*(admin|root|sudo|privilege)
Also: iam\.(create_role|attach_policy|put_role_policy)
```

**ASI08-SC02** | Score: 70 | Confidence: high  
Label: LLM-generated credentials used in authentication  
```
Grep: (auth|login|authenticate)\s*\(.*\b(response|output|content)\b
Also: token\s*=.*\.content\b
Also: password\s*=.*\b(response|output)\b
Also: jwt.*=.*\b(response|content)\b
```

---

### SIGNAL: OW-ASI09 — Critical Decision Without Validation

**ASI09-SC01** | Score: 75 | Confidence: deterministic  
Label: No try/except or fallback around LLM invocation  
```
Grep: \.invoke\s*\(|\.run\s*\(|\.predict\s*\(|\.complete\s*\(
```
For each LLM invocation found: check if it is wrapped in try/except. If not → fires.

**ASI09-SC02** | Score: 70 | Confidence: high  
Label: LLM output used to drive financial, medical, or safety-critical decisions without validation  
```
Grep: (payment|charge|transfer|diagnosis|prescription|medication|deploy|shutdown)\s*.*\b(response|output|content)\b
Also: stripe\.(charge|create).*\b(response|output)\b
Also: (delete|destroy|terminate)\s*\(.*\b(response|output|content)\b
```

---

### SIGNAL: OW-ASI10 — Cascading Failures

**ASI10-SC01** | Score: 60 | Confidence: medium  
Label: Exceptions from tools propagate to agent without containment  
```
Grep: raise\s+\w+Error\s*\(|raise\s+Exception\s*\(
```
Check if tool functions re-raise exceptions without graceful handling back to agent level.

**ASI10-SC02** | Score: 55 | Confidence: medium  
Label: No retry limit or circuit breaker on LLM calls  
```
Grep: for.*retry|while.*retry|@retry|tenacity|backoff
```
Fire if NO retry-limiting mechanism exists anywhere in the codebase. Inverse check.

---

## PHASE 4 — SEMANTIC SUB-CHECK ANALYSIS

For each semantic sub-check flagged above, read the relevant files identified in Phase 3 and make a reasoned determination. Use these instructions:

### LLM01-SC03: Missing input validation before LLM call
Read files containing LLM invocations. Look for any function that validates/sanitizes input (regex check, content filter, allowlist/blocklist, HTML escaping) between receiving user input and calling the LLM. If absent for most entry points → fires (score 70, high confidence).

### LLM02-SC04: LLM output returned without filtering
Read files that return LLM responses to users. Look for any output filtering, content check, or PII scrubbing before the response leaves the system. If absent → fires (score 60, medium).

### LLM04-SC02: User-controllable training data source
Read RAG ingestion code. If user-uploaded content feeds vector stores without sanitization or content policy check → fires (score 60, medium).

### LLM06-SC03: No rate limiting on agent actions
Read agent executor/graph code. Look for rate limiting decorators, counters, or sleep/throttle between tool calls. If absent from high-frequency tool loops → fires (score 70, medium).

### LLM07-SC02: No check for system prompt echoing
Read response post-processing code. Look for any check that strips or redacts system prompt content before returning to user. If absent → fires (score 65, low).

### LLM08-SC02: Retrieved docs not filtered before LLM
Read RAG chain code. Look for a validation/filtering step between retriever output and LLM context construction. If absent → fires (score 55, low).

### LLM09-SC02: No grounding for factual domains
Read agent description and tool list. If the agent is described as handling factual/medical/legal/financial queries but no RAG or citation mechanism exists → fires (score 45, skeletal).

### LLM10-SC04: No token counting or cost monitoring
Read agent loop code. Look for `get_openai_callback()`, `token_counter`, `usage` tracking, or any cost limit guard. If entirely absent → fires (score 55, medium).

### ASI01-SC02: No goal boundary validation
Read agent/crew initialization. Look for any scope constraints, allowed_actions list, or goal validation logic. If goal is set freely from external input with no constraints → fires (score 75, medium).

### ASI02-SC03: Tool output drives privileged op without validation
Read tool chains. Look for patterns where one tool's raw string output directly becomes another privileged tool's input (file path, command, URL) without parsing or validation → fires (score 80, high).

### ASI03-SC02: Input from other agents not validated
Read multi-agent orchestration code. Look for schema validation (Pydantic, TypedDict) on messages received from sub-agents. If absent → fires (score 70, medium).

### ASI04-SC01: High-impact tools without approval
For each high-impact tool (file delete/write, email send, API call, DB mutation) found in Phase 3, read the tool definition. If there is no `interrupt_before`, `confirmation_required`, or human approval step before execution → fires (score 85, high).

### ASI05-SC02: Memory grows without pruning
Read memory initialization code. Look for `max_token_limit`, `k=N`, or `ConversationSummaryBufferMemory`. If using `ConversationBufferMemory()` with no limit or unbounded list → fires (score 65, medium).

### ASI06-SC02: Arbitrary external URL calls
Read tool definitions making HTTP calls. If URL is constructed from user input without an allowlist → fires (score 65, medium).

### ASI07-SC02: No audit logging
Search entire codebase for any structured logging of tool calls (function entry/exit log with params, decision log). If completely absent → fires (score 75, high).

### ASI08-SC02: LLM credentials used for auth
(Already partially covered by grep) — Read authentication code. Confirm if LLM output is ever passed as credentials → fires (score 70, high).

### ASI09-SC01: No try/except on LLM calls
For each LLM invocation found in Phase 3, read its surrounding context. If not wrapped in try/except → fires.

### ASI09-SC02: Critical decisions from LLM output
Read agent logic. If LLM output directly modifies databases, sends emails, makes payments, controls infrastructure, or issues commands without a validation/confirmation layer → fires (score 70, high).

### ASI10-SC01: Uncaught exception propagation
Read tool implementations. Look for bare `raise` or unhandled exceptions that would crash the agent loop rather than returning an error state → fires (score 60, medium).

### ASI10-SC02: No retry limit
(Already partially covered by grep) — If no retry library (tenacity, backoff) and no explicit retry loop with max_attempts is found → fires (score 55, medium).

---

## PHASE 5 — FRAMEWORK-SPECIFIC CHECKS

Run additional checks based on detected frameworks:

### LangChain / LangGraph
```
Grep: allow_dangerous_deserialization\s*=\s*True               → fires LLM03-SC02 (if not already)
Grep: verbose\s*=\s*True                                        → fires LLM02-SC03 (if not already)
Grep: handle_parsing_errors\s*=\s*False|handle_parsing_errors  → note if True (good) or absent (bad)
Grep: return_direct\s*=\s*True                                  → review if on sensitive tool
Grep: \.compile\s*\(\s*\)                                       → fires ASI04-SC02 if no interrupt_before
```

### OpenAI SDK
```
Grep: parallel_tool_calls\s*=\s*True                           → fires ASI05-SC01
Grep: client\.chat\.completions\.create\s*\((?![^)]*max_tokens)   → fires LLM10-SC01
```

### Anthropic SDK
```
Grep: client\.messages\.create\s*\((?![^)]*max_tokens)            → fires LLM10-SC01
Grep: stream\s*=\s*True                                         → check for error recovery in streaming
```

### Google ADK
```
Grep: safety_settings\s*=.*NONE|block_none|HarmBlockThreshold\.BLOCK_NONE  → fires LLM09-SC01 score 70
Grep: generation_config.*temperature.*[01]\.[89]               → fires LLM09-SC01 if not already
```

### CrewAI
```
Grep: allow_delegation\s*=\s*True                              → fires ASI01-SC02
Grep: Agent\s*\([^)]*\)(?![^)]*max_iter)                      → fires LLM06-SC04 if max_iter absent
Grep: memory\s*=\s*True(?![^)]*memory_config)                 → fires ASI05-SC02
```

---

## PHASE 6 — SCORE CALCULATION

After completing all sub-check analysis, calculate scores using this exact algorithm:

### Step 6.1: Collect fired sub-checks
For each fired sub-check, note: signal_id, sub_check_id, score, confidence_tier.

### Step 6.2: Per-signal score
For each signal that has at least one fired sub-check:
```
fired_scores = [sub_check.score for sub_check in signal.fired_subchecks]
if len(fired_scores) == 1:
    signal_raw_score = fired_scores[0]
else:
    signal_raw_score = max(fired_scores) * 0.6 + mean(fired_scores excluding max) * 0.4

signal_raw_score = min(signal_raw_score, 100)
```

### Step 6.3: Composite scores
Separate signals into LLM (OW-LLM01–10) and ASI (OW-ASI01–10):
```
fired_llm_signal_scores = [signal.raw_score for signal in fired_llm_signals]
fired_asi_signal_scores = [signal.raw_score for signal in fired_asi_signals]

if len(fired_llm_signal_scores) == 0:
    llm_composite = 0
elif len(fired_llm_signal_scores) == 1:
    llm_composite = fired_llm_signal_scores[0]
else:
    llm_composite = max(fired_llm_signal_scores) * 0.6 + mean(fired_llm_signal_scores excluding max) * 0.4

# Same formula for asi_composite
```

### Step 6.4: Attack chain detection
Check if the following combinations of sub-checks ALL fired. If yes, note the chain and amplifier:

| Chain ID | Required Sub-checks | Amplifier |
|---|---|---|
| RCE-via-agent | LLM05-SC01 AND ASI02-SC01 | ×1.35 |
| prompt-to-exfil | LLM01-SC01 AND ASI06-SC01 | ×1.30 |
| unbounded-execution | LLM06-SC04 AND ASI05-SC01 AND LLM10-SC03 | ×1.25 |
| supply-chain-priv-esc | LLM03-SC03 AND ASI08-SC01 | ×1.20 |
| hitl-bypass | ASI04-SC01 AND LLM06-SC01 | ×1.15 |

Apply the highest matching amplifier (or 1.0 if none).

### Step 6.5: Final scores and band
```
amplifier = max(matched_chain.amplifier for each matched chain, default 1.0)

final_llm_score = min(llm_composite * amplifier, 100)
final_asi_score = min(asi_composite * amplifier, 100)
composite_score = (final_llm_score + final_asi_score) / 2

band:
  composite >= 85  → CRITICAL
  composite >= 60  → HIGH
  composite >= 35  → MEDIUM
  composite >= 15  → LOW
  else             → CLEAN
```

---

## PHASE 7 — GENERATE REPORT

Generate the full report. If the user requested terminal markdown (default), output directly to terminal. If HTML or JSON was requested, write those files as well.

### ANSI Color Palette

Use these ANSI escape sequences literally in terminal output (they render in all POSIX terminals and Claude Code's CLI):

```
RESET    = \033[0m
BOLD     = \033[1m
DIM      = \033[2m

C_CYAN   = \033[1;96m   ← header box, section dividers, signal IDs
C_WHITE  = \033[1;97m   ← score numbers, labels
C_RED    = \033[1;91m   ← CRITICAL severity, FIRED badges, eval/exec finds
C_ORANGE = \033[38;5;208m  ← HIGH severity, attack chain warnings
C_YELLOW = \033[1;93m   ← MEDIUM severity, FIX: labels
C_BLUE   = \033[1;94m   ← LOW severity
C_GREEN  = \033[1;92m   ← CLEAN ✓, passing checks, strengths
C_GRAY   = \033[38;5;244m  ← file paths, metadata, dim info
```

**Band color mapping:**
- CRITICAL (≥85) → C_RED
- HIGH (60–84) → C_ORANGE
- MEDIUM (35–59) → C_YELLOW
- LOW (15–34) → C_BLUE
- CLEAN (0–14) → C_GREEN

**Score number color:**
- score ≥ 85 → C_RED
- score ≥ 60 → C_ORANGE
- score ≥ 35 → C_YELLOW
- score < 35 → C_BLUE

### Terminal Output Template

Apply colors as annotated. Every color sequence must end with RESET (`\033[0m`).

```
{C_CYAN}╔══════════════════════════════════════════════════════════════════════╗
║  dp-scan — DapplePot Agent Security Review                          ║
║  OWASP LLM Top 10 (2025) · OWASP Agentic Security Initiative Top 10 ║
╚══════════════════════════════════════════════════════════════════════╝{RESET}

{C_WHITE}COMPOSITE RISK SCORE:{RESET} {BAND_COLOR}{composite_score} / 100   BAND: {BAND}{RESET}
{DIM}Frameworks detected:{RESET} {comma-separated list}
{DIM}Attack chains detected:{RESET} {chain_id (×amp) in C_ORANGE, or "none" in C_GREEN}
{DIM}Sub-checks fired:{RESET} {C_WHITE}{fired_count} / 58{RESET}   {DIM}Signals triggered:{RESET} {C_WHITE}{signal_count} / 20{RESET}
{DIM}Files scanned:{RESET} {file_count}

{C_CYAN}══ LLM SIGNALS ══════════════════════════════════════════════════════{RESET}

{For each OW-LLM01 through OW-LLM10:}

{If FIRED:}
{C_CYAN}OW-LLMxx{RESET}  {C_RED}FIRED{RESET}   score: {SCORE_COLOR}{signal_raw_score}{RESET}  {SEVERITY_COLOR}[{SEVERITY}]{RESET}
{For each fired sub-check:}
  ├─ {C_WHITE}{SUB_CHECK_ID}{RESET}  {C_RED}FIRED{RESET}  {SCORE_COLOR}{score}{RESET}  {C_GRAY}[{confidence_tier}]{RESET}  {label}
  │  {C_GRAY}→ {file_path}:{line_number}  `{matched_code_snippet}`{RESET}
  │  {C_YELLOW}FIX:{RESET} {one-line fix}
{Last sub-check uses └─ instead of ├─}

{If CLEAN:}
{C_CYAN}OW-LLMxx{RESET}  {C_GREEN}CLEAN ✓{RESET}

{C_CYAN}══ ASI SIGNALS (Agentic Security) ═══════════════════════════════════{RESET}

{Same format for OW-ASI01 through OW-ASI10}

{C_CYAN}══ ATTACK CHAINS ════════════════════════════════════════════════════{RESET}

{For each detected attack chain:}
{C_ORANGE}⚠  {chain_id} (×{amplifier}){RESET}
   {sub_check_1} + {sub_check_2} {+ sub_check_3}: {one-sentence description}
   {C_GRAY}Amplified composite risk: {pre_amp} → {post_amp}{RESET}

{If no chains:}
{C_GREEN}✓ No attack chains detected.{RESET}

{C_CYAN}══ REMEDIATION — PRIORITY ORDER ════════════════════════════════════{RESET}

{For each fired signal sorted by score descending:}
{index}. {SEVERITY_COLOR}[{SEVERITY}]{RESET} {C_WHITE}{OW-SIGNALxx}{RESET} — {Signal Name}   {C_GRAY}score: {score}{RESET}
   {1-sentence description}
   {C_YELLOW}Fix steps:{RESET}
   a. {step 1}
   b. {step 2}
   c. {step 3}
   {C_GRAY}Framework: {framework-specific snippet}{RESET}

{C_CYAN}══ CLEAN SIGNALS ════════════════════════════════════════════════════{RESET}
{C_GREEN}{space-separated list of clean signal IDs with ✓}{RESET}

{C_CYAN}══ SCAN METADATA ════════════════════════════════════════════════════{RESET}
{C_GRAY}Scan completed: {timestamp}
Scanner version: dp-scan 1.0.0
Standards: OWASP LLM Top 10 (2025) · OWASP ASI Top 10 (2026)
Install: https://github.com/dapplepot/dapplepot-agent-scan{RESET}
```

**Fix guidance by signal (embed in remediation section):**

- **OW-LLM01**: Use `ChatPromptTemplate.from_messages([("system","..."),("human","{user_input}")])` — never f-string user data into prompts.
- **OW-LLM02**: Rotate secrets to env vars. Use `python-decouple` or AWS Secrets Manager. Add PII redaction before logging.
- **OW-LLM03**: Pin model versions (`gpt-4o-2024-11-20`, `claude-opus-4-8-20251101`). Remove `allow_dangerous_deserialization`. Audit plugin sources.
- **OW-LLM04**: Add content policy filter before `add_documents()`. Validate document sources. Use hash-based dedup.
- **OW-LLM05**: Replace `eval()`/`exec()` with `PydanticOutputParser`. For SQL: use parameterized queries. For HTML: use `markupsafe.escape()`.
- **OW-LLM06**: Add `max_iterations=10, handle_parsing_errors=True` to AgentExecutor. Wrap destructive tools with `HumanApprovalCallbackHandler`.
- **OW-LLM07**: Move system prompts to server-side env vars. Add output filter that strips system prompt content.
- **OW-LLM08**: Add query sanitization before `similarity_search()`. Filter retrieved docs through a content policy before injecting into context.
- **OW-LLM09**: Lower temperature to ≤0.2 for factual/critical tasks. Add RAG with source citations.
- **OW-LLM10**: Always set `max_tokens`. Wrap async LLM calls in `asyncio.wait_for(coro, timeout=30)`. Set `recursion_limit=10` in LangGraph.
- **OW-ASI01**: Validate agent goals against an allowlist before execution. Never accept dynamic goal updates from untrusted sources.
- **OW-ASI02**: Remove `ShellTool`/`BashTool` from production. Replace with scope-limited tools. Add `@require_permission` decorator.
- **OW-ASI03**: Add HMAC signatures to inter-agent messages. Validate all agent inputs with Pydantic schemas.
- **OW-ASI04**: Add `interrupt_before=["tools"]` to LangGraph compile. Use `HumanApprovalCallbackHandler` for destructive operations.
- **OW-ASI05**: Use `asyncio.Semaphore(5)` to limit parallel tool calls. Set `max_token_limit` on memory. Limit `ThreadPoolExecutor(max_workers=4)`.
- **OW-ASI06**: Add an allowlist of permitted external domains. Strip sensitive fields before passing to HTTP tools.
- **OW-ASI07**: Make agent instructions read-only. Add structured audit logging via `structlog` for all tool calls.
- **OW-ASI08**: Apply least-privilege to all tools. Validate all credentials through proper auth systems — never from LLM output.
- **OW-ASI09**: Wrap all LLM invocations in try/except. Validate critical LLM outputs with Pydantic before acting. Add fallback paths.
- **OW-ASI10**: Catch exceptions in tools, return error state to agent. Add `tenacity.retry` with `stop_after_attempt(3)` and exponential backoff.

---

## PHASE 8 — HTML REPORT (if requested)

If the user requested an HTML report, write a file `dp-scan-report.html` with:
- Dark-mode design
- Risk band displayed as a colored score card (green/blue/amber/orange/red)
- Collapsible signal cards with sub-check drill-downs
- Attack chains highlighted in amber warning boxes
- Remediation section with code snippets in syntax-highlighted blocks
- Footer with scan metadata

Use inline CSS only (no external dependencies). The file must open in any browser without internet access.

---

## PHASE 9 — JSON REPORT (if requested)

If the user requested a JSON report, write `dp-scan-report.json` with this schema:

```json
{
  "scanner": "dp-scan",
  "version": "1.0.0",
  "scanPath": "...",
  "scannedAt": "ISO-8601 timestamp",
  "frameworksDetected": ["LangChain", "..."],
  "compositeScore": 72,
  "compositeLlmScore": 68,
  "compositeAsiScore": 76,
  "riskBand": "high",
  "amplifier": 1.25,
  "attackChainsDetected": ["unbounded-execution"],
  "subChecksFired": 14,
  "signalsFired": 8,
  "llmSignalStatus": {
    "OW-LLM01": {
      "status": "fired",
      "rawScore": 85,
      "sub_checks": {
        "LLM01-SC01": {
          "status": "fired",
          "score": 85,
          "confidenceTier": "deterministic",
          "label": "User input directly interpolated into prompt string",
          "detail": "agent/chain.py:42 — f-string with user_input variable",
          "fix": "Use ChatPromptTemplate.from_messages with explicit role separation"
        }
      }
    }
  },
  "asiSignalStatus": { "...": "..." },
  "remediationCards": [
    {
      "owaspSignalId": "OW-LLM05",
      "title": "Insecure Output Handling",
      "description": "LLM output passed to eval()",
      "frequency": 1,
      "severity": "critical",
      "fixSteps": ["Remove eval(response.content)", "..."],
      "codeSnippet": "from langchain_core.output_parsers import JsonOutputParser"
    }
  ]
}
```

---

*dp-scan is part of the DapplePot open-source security suite.*  
*Standards: OWASP LLM Top 10 (2025) · OWASP Agentic Security Initiative (ASI) Top 10 (2026)*  
*Install: `mkdir -p ~/.claude/skills/dp-scan && curl -fsSL https://raw.githubusercontent.com/dapplepot/dapplepot-agent-scan/main/skills/scan/SKILL.md > ~/.claude/skills/dp-scan/SKILL.md`*
