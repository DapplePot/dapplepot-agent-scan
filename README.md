# dp-scan — DapplePot Agent Security Scan

> OWASP security audit for AI agent codebases.  
> OWASP LLM Top 10 (2025) · OWASP Agentic Security Initiative Top 10 (2026)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Standards: OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Standards: OWASP ASI Top 10](https://img.shields.io/badge/OWASP-ASI%20Top%2010-orange)](https://owasp.org/www-project-agentic-security/)

---

## What it does

`dp-scan` audits any AI agent codebase against two OWASP security standards, producing a scored, actionable security report.

**20 signals. 58 sub-checks. 5 attack chain combinations. One command.**

| Layer | Standard | Signals |
|---|---|---|
| LLM | OWASP LLM Top 10 (2025) | OW-LLM01 – OW-LLM10 |
| Agentic | OWASP ASI Top 10 (2026) | OW-ASI01 – OW-ASI10 |

### Frameworks supported

| Framework | Checks |
|---|---|
| LangChain 0.x / 0.3.x | 22 checks incl. deserialization, max_iterations, verbose logging |
| LangGraph 0.x | interrupt_before, recursion_limit, state management |
| OpenAI SDK | max_completion_tokens, parallel_tool_calls, response validation |
| Anthropic SDK | max_tokens, tool result validation, streaming error recovery |
| Google ADK / Gemini | safety_settings, generation_config, tool permissions |
| CrewAI | allow_delegation scope, max_iter, shared memory isolation |

### What you get

- **Composite risk score** (0–100) with band: `clean` / `low` / `medium` / `high` / `critical`
- **Per-signal breakdown** — every signal shows `FIRED` or `CLEAN ✓`
- **Sub-check drill-down** — each fired check shows the file:line, matched code, and a one-line fix
- **Attack chain detection** — cross-signal combos that amplify risk (up to ×1.35)
- **Prioritized remediation cards** — ordered by severity, with framework-specific fix code
- **Three output formats** — terminal markdown, HTML report, JSON (CI-friendly)

---

## Install

### Option 1 — Claude Code plugin (recommended)

Add the plugin marketplace and install in two commands:

```
/plugin marketplace add dapplepot/dapplepot-agent-scan
/plugin install dp-scan@dapplepot-agent-scan
```

Then reload and invoke:

```
/reload-plugins
/dp-scan:scan
```

### Option 2 — One-liner curl (no marketplace needed)

```bash
mkdir -p ~/.claude/skills/dp-scan && \
  curl -fsSL https://raw.githubusercontent.com/dapplepot/dapplepot-agent-scan/main/skills/scan/SKILL.md \
  > ~/.claude/skills/dp-scan/SKILL.md
```

Invoke as `/dp-scan` directly (no namespace needed for manually installed skills).

### Option 3 — Project-level (share with your team)

```bash
mkdir -p .claude/skills/dp-scan
curl -fsSL https://raw.githubusercontent.com/dapplepot/dapplepot-agent-scan/main/skills/scan/SKILL.md \
  > .claude/skills/dp-scan/SKILL.md

git add .claude/skills/dp-scan/SKILL.md
git commit -m "chore: add dp-scan agent security skill"
```

Every developer who clones the repo gets the skill automatically — invoke as `/dp-scan`.

### Other agents (Cursor, Copilot, Codex, Windsurf, Gemini CLI)

Copy the contents of `skills/scan/SKILL.md` and paste it as a custom system prompt or instruction rule in your agent's config. The skill is plain instruction format — no Claude-specific APIs required.

---

## Usage

### Basic scan (current directory)

```
/dp-scan:scan          # if installed via plugin
/dp-scan               # if installed via curl / project-level
```

The skill will ask:
1. Which directory to scan (default: `.`)
2. Which format to output (default: terminal markdown)

### Scan a specific path

When prompted for scan path, enter a relative or absolute path:
```
> Scan path: ./src/agents
```

### Get a JSON report for CI/CD

When prompted for format, choose `JSON file`. This writes `dp-scan-report.json` that integrates with any CI pipeline.

Example GitHub Actions step:
```yaml
- name: Security scan
  run: claude -p "/dp-scan" --output dp-scan-report.json
  
- name: Check risk band
  run: |
    BAND=$(cat dp-scan-report.json | jq -r '.riskBand')
    if [ "$BAND" = "critical" ] || [ "$BAND" = "high" ]; then
      echo "Security scan failed: $BAND risk"
      exit 1
    fi
```

---

## Report example

```
╔══════════════════════════════════════════════════════════════════════╗
║  dp-scan — DapplePot Agent Security Review                          ║
║  OWASP LLM Top 10 (2025) · OWASP Agentic Security Initiative Top 10 ║
╚══════════════════════════════════════════════════════════════════════╝

COMPOSITE RISK SCORE: 72 / 100   BAND: HIGH
Frameworks detected: LangChain, LangGraph
Attack chains detected: hitl-bypass (×1.15), unbounded-execution (×1.25)
Sub-checks fired: 14 / 58   Signals triggered: 8 / 20
Files scanned: 23

══ LLM SIGNALS ══════════════════════════════════════════════════════

OW-LLM01  FIRED   score: 85  [CRITICAL]
  ├─ LLM01-SC01  FIRED  85  [deterministic]  User input directly in f-string prompt
  │  → agent/chain.py:42  `f"Answer this: {user_input}"`
  │  FIX: Use ChatPromptTemplate.from_messages with explicit role separation
  └─ LLM01-SC03  FIRED  70  [high]  No input sanitization before LLM invoke
     → agent/chain.py:40  No validate() call found before .invoke()
     FIX: Add input validation / content filtering before chain invocation

OW-LLM05  FIRED   score: 95  [CRITICAL]
  └─ LLM05-SC01  FIRED  95  [deterministic]  LLM output executed via eval()
     → agent/executor.py:88  `eval(response.content)`
     FIX: Use PydanticOutputParser — NEVER eval LLM output

...
```

---

## What dp-scan does NOT check

- Runtime behavior (it is a static analysis tool)
- Secrets that are fully externalized (env vars are correct — dp-scan won't flag them unless hardcoded)
- Infrastructure security (IAM, network policies) — use cloud security scanners for those
- Model weights or training data integrity

---

## Signal reference

See [SIGNAL_REGISTRY.md](SIGNAL_REGISTRY.md) for the complete reference of all 20 signals and 58 sub-checks with their scoring weights and confidence tiers.

See [SCORING.md](SCORING.md) for the full scoring algorithm documentation.

---

## Contributing

1. Fork the repo
2. Add or improve a sub-check in `skills/scan/SKILL.md`
3. Add a matching test case in `examples/`
4. Open a PR with the signal ID in the title (e.g., `feat(LLM05): add SC05 for template injection`)

All sub-checks must include: signal ID, sub-check ID, score (0–100), confidence tier, grep pattern or semantic instruction, and fix guidance.

---

## License

MIT © DapplePot




