# Scoring Algorithm — dp-scan v1.0.0

This document is the canonical reference for contributors.

---

## Overview

dp-scan produces four scores:
1. **Sub-check score** — raw weight of an individual fired check (0–100)
2. **Signal raw score** — composite of fired sub-checks within one OWASP signal
3. **Framework composite** — composite of fired signals within LLM or ASI layer
4. **Final composite** — average of LLM and ASI composites, with attack-chain amplification

---

## Step 1: Sub-check scores

Each sub-check has a pre-defined score (0–100). Scores are fixed in the signal registry and represent the maximum risk contribution if the check fires. They are **not adjusted** by the scanner at runtime — confidence tier is a metadata label only.

| Score range | Interpretation |
|---|---|
| 90–100 | Critical finding — direct exploitation path |
| 70–89 | High severity — significant attack surface |
| 50–69 | Medium severity — risk depends on context |
| 30–49 | Low severity — defense-in-depth gap |
| 0–29 | Informational — best practice deviation |

---

## Step 2: Signal raw score

When one or more sub-checks fire within a signal, compute the signal's raw score:

```python
fired = [sc.score for sc in signal.sub_checks if sc.status == "fired"]

if len(fired) == 0:
    signal_raw_score = 0
elif len(fired) == 1:
    signal_raw_score = fired[0]
else:
    max_score = max(fired)
    others = [s for s in fired if s != max_score]  # excludes one instance of max
    signal_raw_score = max_score * 0.6 + mean(others) * 0.4

signal_raw_score = min(signal_raw_score, 100)
```

**Rationale**: The most severe finding dominates (60%), but additional fired checks are additive (40%), reflecting co-occurring vulnerabilities increasing overall risk.

---

## Step 3: Framework composite scores

Compute separately for LLM signals (OW-LLM01–10) and ASI signals (OW-ASI01–10):

```python
def composite(fired_signal_scores):
    if len(fired_signal_scores) == 0:
        return 0
    if len(fired_signal_scores) == 1:
        return fired_signal_scores[0]
    max_score = max(fired_signal_scores)
    others = [s for s in fired_signal_scores if s != max_score]
    return min(max_score * 0.6 + mean(others) * 0.4, 100)

llm_composite = composite([s.raw_score for s in fired_llm_signals])
asi_composite = composite([s.raw_score for s in fired_asi_signals])
```

---

## Step 4: Attack chain detection

After scoring, check which attack chains apply. A chain fires if **all** of its required sub-checks fired.

```python
ATTACK_CHAINS = [
    {
        "id": "RCE-via-agent",
        "checks": ["LLM05-SC01", "ASI02-SC01"],
        "amplifier": 1.35,
        "description": "eval(LLM output) + unrestricted shell tool = Remote Code Execution path"
    },
    {
        "id": "prompt-to-exfil",
        "checks": ["LLM01-SC01", "ASI06-SC01"],
        "amplifier": 1.30,
        "description": "Prompt injection feeds directly into data exfiltration tool"
    },
    {
        "id": "unbounded-execution",
        "checks": ["LLM06-SC04", "ASI05-SC01", "LLM10-SC03"],
        "amplifier": 1.25,
        "description": "No iteration limit + unbounded parallel calls + recursive loops = runaway cost/DoS"
    },
    {
        "id": "supply-chain-priv-esc",
        "checks": ["LLM03-SC03", "ASI08-SC01"],
        "amplifier": 1.20,
        "description": "Untrusted plugin combined with privilege-escalation tool"
    },
    {
        "id": "hitl-bypass",
        "checks": ["ASI04-SC01", "LLM06-SC01"],
        "amplifier": 1.15,
        "description": "High-impact tools execute with no human-in-the-loop gate"
    },
]

fired_check_ids = {sc.id for sc in all_fired_sub_checks}
matched_chains = [
    chain for chain in ATTACK_CHAINS
    if all(cid in fired_check_ids for cid in chain["checks"])
]

amplifier = max((chain["amplifier"] for chain in matched_chains), default=1.0)
```

Only the **highest amplifier** is applied (chains do not stack multiplicatively).

---

## Step 5: Final composite and risk band

```python
final_llm_score = min(llm_composite * amplifier, 100)
final_asi_score = min(asi_composite * amplifier, 100)
composite_score = (final_llm_score + final_asi_score) / 2

if composite_score >= 85:
    band = "critical"
elif composite_score >= 60:
    band = "high"
elif composite_score >= 35:
    band = "medium"
elif composite_score >= 15:
    band = "low"
else:
    band = "clean"
```

---

## Worked example

**Codebase**: LangChain agent with these findings:
- LLM05-SC01 fired (score 95) — `eval(response.content)` found
- LLM06-SC04 fired (score 85) — `AgentExecutor()` without `max_iterations`
- ASI02-SC01 fired (score 90) — `ShellTool()` in tools list
- LLM10-SC01 fired (score 75) — no `max_tokens` on `ChatOpenAI()`

**Signal scores:**
```
OW-LLM05: only SC01 fired → raw_score = 95
OW-LLM06: only SC04 fired → raw_score = 85
OW-LLM10: only SC01 fired → raw_score = 75
OW-ASI02: only SC01 fired → raw_score = 90
```

**Composite:**
```
LLM signals fired: [95, 85, 75]
llm_composite = max(95,85,75)*0.6 + mean(85,75)*0.4
             = 95*0.6 + 80*0.4
             = 57 + 32 = 89

ASI signals fired: [90]
asi_composite = 90
```

**Attack chains:**
- RCE-via-agent: LLM05-SC01 ✓ + ASI02-SC01 ✓ → matches, amplifier ×1.35

```
final_llm = min(89 * 1.35, 100) = 100 (capped)
final_asi = min(90 * 1.35, 100) = 100 (capped)
composite_score = (100 + 100) / 2 = 100
band = "critical"
```

---

## Design decisions

**Why 0.6/0.4 split?** The most severe finding is the primary attack vector; additional findings compound it but don't simply add. This prevents a "many low-score findings = critical" false positive.

**Why cap at 100?** Scores are percentages of maximum risk. Attack chains represent compound risk but the codebase can't be "more than fully vulnerable."

**Why per-framework composites?** LLM-layer risks (prompt injection, output handling) and agentic-layer risks (goal hijacking, inter-agent compromise) require different mitigations. Separating them helps prioritize remediation.
