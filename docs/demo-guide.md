# Live Hackathon Demo Guide

Chaperone provides an end-to-end adversarial demonstration (`backend/app/demo/hackathon_demo.py` and `backend/app/demo/prompt_injection_demo.py`) showing **Safe autonomy. Human control.** against untrusted instructions.

## Execution Modes (`auto` | `llm` | `fallback`)

Both demo modules clearly tag telemetry output with `execution_mode`:
- **`real_llm`:** Runs an OpenAI-compatible `/chat/completions` multi-turn tool-calling loop (`backend/app/demo/llm_agent.py`) exclusively over `ChaperoneMCPClient` (`tools/list` contains **zero** credentials; `ChaperoneMCPServer` binds agent auth out-of-band).
- **`scripted_fallback`:** Deterministic local scenario runner requiring zero external network access or API billing.

### Running via CLI

```powershell
cd backend

# Default (--mode auto): uses real LLM if CHAPERONE_LLM_API_KEY / OPENAI_API_KEY is set, else scripted_fallback
python -m app.demo.hackathon_demo

# Force deterministic offline fallback
python -m app.demo.hackathon_demo --mode fallback

# Require live OpenAI-compatible LLM (fails loudly if API key is unset)
$env:CHAPERONE_LLM_API_KEY="sk-..."
$env:CHAPERONE_LLM_BASE_URL="https://api.openai.com/v1"   # Optional override
$env:CHAPERONE_LLM_MODEL="gpt-4o-mini"                    # Optional override
python -m app.demo.hackathon_demo --mode llm
```

## What the Hackathon Demo Demonstrates

1. **Legitimate Task Succeeds:** Agent summarizes permitted workspace documents via `file_tool.list` / `file_tool.read` and creates an internal email draft (`ALLOW`, verified by `VerificationEngine`).
2. **Prompt Injection Blocked (`MALICIOUS`):** Hidden adversarial instructions embedded inside an untrusted document attempt to exfiltrate `private/secrets.txt` and email an external attacker address (`evil@attacker.example`).
   - `PolicyEngine` deterministically rejects `private/secrets.txt` (`DENY`).
   - `email_tool.send` triggers `REQUIRE_APPROVAL` (cannot bypass human review).
3. **Human Approval Control:** An authenticated `approver`/`super_admin` session rejects the injected outbound send (`reviewer_id` derived server-side) while approving legitimate operational writes/sends.
4. **Chained Audit Verification:** Inspects `GET /api/v1/audit-events/integrity` showing uninterrupted SHA-256 hash continuity across allowed, denied, pending, and rejected events.
