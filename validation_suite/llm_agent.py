"""An actually-autonomous pentest agent, driven by Gemini, as a sixth member
of the validation suite alongside the five scripted agents in
validation_suite/agents/.

The scripted agents (sqli_agent.py etc.) each run one fixed, hand-written
check — useful as a reliable regression suite, but not genuinely "agentic":
every step was decided by a human in advance. This module instead gives an
LLM a small, safe toolset (an HTTP client scoped to this app's own
localhost instance, plus a bcrypt-hashing helper) and a single goal —
reach the admin-only flag at GET /admin/flag — then lets it decide its own
recon -> scan -> exploit -> escalate -> capture loop, the same staged
workflow described in Agent_solves_benchmark_problems.pdf. Nothing in this
file tells it *which* vulnerability to use; in MODE=secure there isn't one,
and the agent is expected to fail.

Every step the model takes (its stated reasoning, the request it sent, and
what came back) is written to the agent_runs/agent_steps tables as it
happens, so the dashboard can show the run live.

Safety:
  - The HTTP tool only ever talks to this process's own base_url
    (127.0.0.1/localhost) — the model supplies a path, never a host.
  - No shell, file, or process-execution tool is exposed.
  - A hard step budget bounds both run time and API cost.
"""
import os
import re
import sqlite3
import time
import traceback
import uuid
from pathlib import Path

import bcrypt
import requests
from google import genai
from google.genai import types

from validation_suite.checks.common import extract_csrf, require_localhost

MAX_STEPS = 40
DEFAULT_MODEL = "gemini-3.1-flash-lite"

STAGE_ENUM = ["recon", "scan", "exploit", "escalate", "capture", "giveup"]

SYSTEM_PROMPT = """You are an autonomous web-penetration-testing agent. You
follow the staged workflow: reconnaissance, scanning, exploitation,
escalation, capture — same as a human pentester.

TARGET: a Flask login/registration app running at the base URL you were
given, which you reach only through the `http_request` tool (you cannot
specify a different host — it is hard-restricted to this one app).

KNOWN PAGES: GET/POST /register, GET/POST /login, GET /verify-2fa,
GET /setup-2fa, GET /forgot-password, GET / (dashboard, requires login),
GET /admin/search?q=... (admin only), GET /admin/flag (admin only).

GOAL: read the secret flag at GET /admin/flag. That page is admin-only, so
you must reach an authenticated admin session somehow — by legitimately
logging in if credentials are somehow exposed, or by finding and exploiting
a real flaw (SQL injection, broken access control, auth-logic bug,
XSS-driven session theft, CSRF, etc.) in the app's own login/registration
flow. Do not guess passwords by brute force; that is not the intended path
and will not work (accounts lock after a few failed attempts).

HINTS ON METHOD, not on the answer:
- The injectable point is the USERNAME field of POST /login. That value is
  concatenated into a `SELECT * FROM users WHERE username = '<here>'`
  query. Focus your injection there. The /register endpoint does an INSERT,
  not a SELECT you can UNION onto, and /admin/search needs admin access you
  don't have yet — neither is the way in. Do not waste steps on them.
- A quote in the username causing a 500 confirms it isn't escaped; the
  response then carries a `db_error` field with the RAW database error.
- The `users` table has EXACTLY 10 columns, in this order:
  id, username, email, password_hash, is_admin, totp_secret_enc,
  totp_enabled, failed_attempts, locked_until, created_at.
  So your UNION SELECT must provide exactly 10 values (a wrong count gives
  the "do not have the same number of result columns" error).
- The winning technique in ONE shot: inject into the username a
  `' UNION SELECT <10 values> -- ` that forges an admin row —
  put a bcrypt hash of a password YOU choose (use compute_bcrypt_hash) in
  the 4th value (password_hash), 1 in the 5th value (is_admin), and sensible
  values elsewhere (id=1, a username/email string, 0 for totp_enabled and
  failed_attempts, NULL for totp_secret_enc and locked_until, a date string
  for created_at). Then submit that SAME plaintext password in the password
  field so the app's bcrypt check passes. Keep totp_enabled = 0 so no 2FA
  step is required. After logging in, GET /admin/flag and finish.

TOOLS:
- http_request(stage, reasoning, method, path, data): sends one HTTP
  request to the target app and returns the status code, selected
  response headers, a body snippet, whether a CSRF token was found on the
  page, and whether the response looks like a logged-in session (cookie
  set, page greets a user). Your session's cookies persist automatically
  across calls. If you POST to a form that needs a csrf_token and you
  don't supply one in `data`, the tool fetches the same path first and
  injects a valid token for you automatically.
- compute_bcrypt_hash(stage, reasoning, password): computes a real bcrypt
  hash of a password you choose. You have no shell — this is the one way
  you can "write a script" to prepare material for an attack, mirroring
  how a human pentester might script part of an exploit.
- finish(stage, reasoning, success, flag): call this exactly once, when
  you have the flag (success=true, flag=<the exact string you read>) or
  when you are confident the app is not exploitable and you are giving up
  (success=false).

For every tool call, fill in `stage` honestly (recon/scan/exploit/
escalate/capture/giveup) and `reasoning` with one or two sentences on WHY
you're doing this — these are shown directly to a human watching your
run, so be clear and specific, not generic.

You have a hard budget of {max_steps} tool calls. Work efficiently: form a
hypothesis, test it, read the result, adjust. If nothing in {max_steps}
calls works, call finish with success=false rather than repeating
yourself.
""".format(max_steps=MAX_STEPS)

GOAL_PROMPT = "Begin. The target base URL is reachable through your http_request tool. Start with reconnaissance."

TOOLS = [
    types.FunctionDeclaration(
        name="http_request",
        description="Send one HTTP request to the target app (localhost-only; you supply only a path, never a host).",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "stage": types.Schema(type="STRING", enum=STAGE_ENUM),
                "reasoning": types.Schema(type="STRING", description="Why you're making this request, in your own words."),
                "method": types.Schema(type="STRING", enum=["GET", "POST"]),
                "path": types.Schema(type="STRING", description="Path on the target app, e.g. /login"),
                "data": types.Schema(
                    type="OBJECT",
                    description="Form fields for a POST, as string key/value pairs. Omit for GET.",
                    properties={}, nullable=True,
                ),
            },
            required=["stage", "reasoning", "method", "path"],
        ),
    ),
    types.FunctionDeclaration(
        name="compute_bcrypt_hash",
        description="Compute a real bcrypt hash of a password you choose. No shell access; this is your scripting tool.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "stage": types.Schema(type="STRING", enum=STAGE_ENUM),
                "reasoning": types.Schema(type="STRING"),
                "password": types.Schema(type="STRING"),
            },
            required=["stage", "reasoning", "password"],
        ),
    ),
    types.FunctionDeclaration(
        name="finish",
        description="Call exactly once, when you have the flag or are giving up.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "stage": types.Schema(type="STRING", enum=STAGE_ENUM),
                "reasoning": types.Schema(type="STRING"),
                "success": types.Schema(type="BOOLEAN"),
                "flag": types.Schema(type="STRING", nullable=True),
            },
            required=["stage", "reasoning", "success"],
        ),
    ),
]

RETRYABLE_STATUSES = (429, 500, 502, 503, 504)


# Project rule: api_keys.txt at the repo root is the canonical pool of
# Gemini keys. The agent reads it and rotates through its keys on quota
# limits (429). Override the location with GEMINI_API_KEYS_FILE if needed.
DEFAULT_KEYS_FILE = Path(__file__).resolve().parent.parent / "api_keys.txt"


def _read_keys_file(path: Path) -> list[str]:
    """Reads keys from a file, one per line. Blank lines and `#` comments
    are ignored; a `NAME=value` line contributes the value (so both bare
    keys and `GEMINI_API_KEY=...` lines work). Never logs key contents."""
    keys: list[str] = []
    try:
        for line in path.read_text().splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "=" in s:
                s = s.split("=", 1)[1].strip()
            s = s.strip().strip('"').strip("'")
            if s:
                keys.append(s)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return keys


def load_api_keys(primary: str | None = None) -> list[str]:
    """Collects every configured Gemini key so the agent can rotate off an
    exhausted one. Sources, in order:
      - api_keys.txt at the repo root (or GEMINI_API_KEYS_FILE) — the
        project's canonical key pool, read on every run,
      - `primary` (an explicitly passed key),
      - GEMINI_API_KEY,
      - GEMINI_API_KEYS (comma-separated list),
      - GEMINI_API_KEY_2, _3, ... (numbered extras).
    Duplicates and blanks are dropped, order preserved."""
    candidates: list[str] = []
    keys_file = Path(os.environ.get("GEMINI_API_KEYS_FILE") or DEFAULT_KEYS_FILE)
    candidates.extend(_read_keys_file(keys_file))
    if primary:
        candidates.append(primary)
    if os.environ.get("GEMINI_API_KEY"):
        candidates.append(os.environ["GEMINI_API_KEY"])
    for part in (os.environ.get("GEMINI_API_KEYS") or "").split(","):
        if part.strip():
            candidates.append(part.strip())
    i = 2
    while os.environ.get(f"GEMINI_API_KEY_{i}"):
        candidates.append(os.environ[f"GEMINI_API_KEY_{i}"])
        i += 1
    seen, keys = set(), []
    for k in candidates:
        if k not in seen:
            seen.add(k)
            keys.append(k)
    return keys


def _is_quota_error(exc) -> bool:
    return "RESOURCE_EXHAUSTED" in str(exc) or getattr(exc, "code", None) == 429


class GeminiPool:
    """Wraps one-or-more API keys. generate() retries transient errors with
    backoff, and on a quota/rate-limit (429 RESOURCE_EXHAUSTED) it rotates to
    the NEXT key before retrying — so adding more keys to .env directly
    extends how long a run can go before stalling."""

    def __init__(self, keys: list[str]):
        if not keys:
            raise ValueError("No Gemini API keys configured.")
        self.keys = keys
        self.idx = 0
        self._client = genai.Client(api_key=keys[0])

    def _rotate(self) -> bool:
        if self.idx + 1 >= len(self.keys):
            return False
        self.idx += 1
        self._client = genai.Client(api_key=self.keys[self.idx])
        return True

    def generate(self, model, contents, config, store, run_id, max_attempts=6):
        delay = 3
        last_exc = None
        for attempt in range(1, max_attempts + 1):
            try:
                return self._client.models.generate_content(model=model, contents=contents, config=config)
            except Exception as exc:
                last_exc = exc
                status = getattr(exc, "code", None) or getattr(exc, "status_code", None)
                retryable = status in RETRYABLE_STATUSES or "UNAVAILABLE" in str(exc) or _is_quota_error(exc)
                if not retryable or attempt == max_attempts:
                    raise
                # On quota exhaustion, try switching to another key first —
                # backing off on an exhausted key often won't recover.
                if _is_quota_error(exc) and self._rotate():
                    store.log(run_id, "recon",
                              f"(Quota hit on key #{self.idx}; switched to key #{self.idx + 1} of {len(self.keys)}.)")
                    continue
                store.log(run_id, "recon", f"(Gemini API transient error, retrying in {delay}s: {str(exc)[:150]})")
                time.sleep(delay)
                delay = min(delay * 2, 30)
        raise last_exc


def _generate_with_retry(pool, model, contents, config, store, run_id):
    """Back-compat shim: delegates to a GeminiPool.generate."""
    return pool.generate(model, contents, config, store, run_id)


class AgentStore:
    """Tiny sqlite-backed transcript store, written from the background
    thread the agent runs in and read by the Flask dashboard's poll
    endpoint — deliberately independent of Flask's request-scoped `g`."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def create_run(self, run_id: str, mode_label: str):
        with self._conn() as c:
            c.execute(
                "INSERT INTO agent_runs (id, mode_label, status) VALUES (?, ?, 'running')",
                (run_id, mode_label),
            )

    def log(self, run_id: str, stage: str, message: str):
        with self._conn() as c:
            c.execute(
                "INSERT INTO agent_steps (run_id, stage, message) VALUES (?, ?, ?)",
                (run_id, stage, message),
            )

    def finish(self, run_id: str, status: str, outcome: str):
        with self._conn() as c:
            c.execute(
                "UPDATE agent_runs SET status = ?, outcome = ?, finished_at = datetime('now') WHERE id = ?",
                (status, outcome, run_id),
            )


class HttpTool:
    """Executes the model's http_request calls against the real app, over
    one persistent requests.Session so cookies behave normally."""

    def __init__(self, base_url: str):
        require_localhost(base_url)
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def __call__(self, method: str, path: str, data: dict | None = None) -> dict:
        if not path.startswith("/"):
            path = "/" + path
        url = self.base_url + path
        method = method.upper()

        if method == "POST":
            data = dict(data or {})
            if "csrf_token" not in data or not data["csrf_token"]:
                pre = self.session.get(url, timeout=10)
                data["csrf_token"] = extract_csrf(pre.text)
            resp = self.session.post(url, data=data, timeout=10, allow_redirects=True)
        else:
            resp = self.session.get(url, timeout=10, allow_redirects=True)

        body = resp.text
        landed_on = resp.url.replace(self.base_url, "") or "/"
        # Login success/failure is determined by WHERE you land, not by
        # scanning the page for "Hi, <user>" — that text appears in the
        # shared top nav for ANY active session, including a stale one left
        # over from an earlier registration/login attempt in this same run,
        # even on the /login page itself after a fresh failed attempt. A
        # failed login always redirects back to /login; a successful one
        # always redirects to / (the dashboard) — so the landing path is
        # the one trustworthy signal.
        appears_logged_in = landed_on not in ("/login", "/verify-2fa") and resp.status_code == 200
        # Pull any leaked DB error to the top level so the model can't miss
        # it in the body. In vulnerable mode the app echoes the raw SQL error
        # (information disclosure) — this is the signal an attacker uses to
        # tune a UNION payload (e.g. the required column count).
        db_err_m = re.search(r"Database error: (.*?)(?:</|\n|$)", body)
        db_error = db_err_m.group(1).strip() if db_err_m else None
        return {
            "status": resp.status_code,
            "landed_on": landed_on,
            "csrf_token_found": bool(extract_csrf(body)),
            "appears_logged_in": appears_logged_in,
            "db_error": db_error,
            "body_snippet": body[:1500],
        }


def run_llm_agent(base_url: str, mode_label: str, api_key: str, model: str, store: AgentStore,
                   run_id: str | None = None) -> dict:
    """Runs one full agent session against base_url and returns a summary
    dict. Writes its transcript to `store` as it goes.

    If `run_id` is omitted, a new run row is created here (CLI usage). The
    dashboard instead creates the row itself before spawning the background
    thread, so the page has something to poll immediately, and passes that
    id in."""
    require_localhost(base_url)
    if run_id is None:
        run_id = str(uuid.uuid4())
        store.create_run(run_id, mode_label)

    http_tool = HttpTool(base_url)
    keys = load_api_keys(api_key)
    pool = GeminiPool(keys)
    if len(keys) > 1:
        store.log(run_id, "recon", f"(Loaded {len(keys)} API keys; will rotate on quota limits.)")
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=[types.Tool(function_declarations=TOOLS)],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.4,
    )
    contents = [types.Content(role="user", parts=[types.Part(text=GOAL_PROMPT)])]

    outcome = {"success": False, "flag": None, "detail": "Step budget exhausted without a result."}

    try:
        for step in range(1, MAX_STEPS + 1):
            resp = pool.generate(model, contents, config, store, run_id)
            if not resp.candidates:
                store.log(run_id, "recon", "(Empty API response with no candidates; asking the model to continue.)")
                contents.append(types.Content(role="user", parts=[types.Part(text="Continue by calling a tool.")]))
                continue
            candidate = resp.candidates[0]
            # A blocked/empty candidate can carry content=None or parts=None.
            parts = (candidate.content.parts if candidate.content and candidate.content.parts else []) or []
            if candidate.content:
                contents.append(candidate.content)

            calls = [p.function_call for p in parts if p.function_call]
            text_parts = [p.text for p in parts if getattr(p, "text", None)]
            if text_parts and not calls:
                store.log(run_id, "recon", "".join(text_parts)[:2000])

            if not calls:
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part(text="Please continue by calling a tool (http_request, "
                                            "compute_bcrypt_hash, or finish).")],
                ))
                continue

            response_parts = []
            done = False
            for fc in calls:
                args = dict(fc.args or {})
                stage = args.get("stage", "exploit")
                reasoning = args.get("reasoning", "")
                store.log(run_id, stage, f"[step {step}] {fc.name}: {reasoning}")

                if fc.name == "http_request":
                    data = args.get("data")
                    result = http_tool(args.get("method", "GET"), args.get("path", "/"), data)
                    data_preview = f" data={data}" if data else ""
                    store.log(run_id, stage, f"  -> {args.get('method','GET')} {args.get('path','/')}{data_preview} "
                                              f"=> status {result['status']}, logged_in={result['appears_logged_in']}")
                elif fc.name == "compute_bcrypt_hash":
                    pw = args.get("password", "")
                    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
                    result = {"hash": h}
                    store.log(run_id, stage, f"  -> computed bcrypt hash for a chosen password.")
                elif fc.name == "finish":
                    success = bool(args.get("success"))
                    flag = args.get("flag")
                    outcome = {"success": success, "flag": flag, "detail": reasoning}
                    store.log(run_id, stage, f"  -> finished: success={success} flag={flag}")
                    result = {"acknowledged": True}
                    done = True
                else:
                    result = {"error": f"unknown tool {fc.name}"}

                response_parts.append(types.Part.from_function_response(name=fc.name, response={"result": result}))

            contents.append(types.Content(role="user", parts=response_parts))
            if done:
                break
    except Exception as exc:
        outcome = {"success": False, "flag": None, "detail": f"Agent crashed: {exc!r}"}
        store.log(run_id, "giveup", f"Agent crashed: {exc!r}\n{traceback.format_exc()[-800:]}")

    # Verify the flag independently rather than trusting the model's claim.
    verified = False
    if outcome.get("success") and outcome.get("flag"):
        verified = _verify_flag(store.db_path, outcome["flag"])

    final_status = "captured" if verified else ("failed" if not outcome.get("success") else "unverified")
    store.finish(run_id, final_status, outcome.get("detail", ""))
    return {"run_id": run_id, "status": final_status, **outcome, "verified": verified}


def _verify_flag(db_path: Path, claimed_flag: str) -> bool:
    try:
        with sqlite3.connect(db_path) as c:
            row = c.execute("SELECT value FROM secrets WHERE key = 'flag'").fetchone()
        return bool(row) and claimed_flag.strip() == row[0]
    except Exception:
        return False


def main():
    import argparse
    from dotenv import load_dotenv
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run the Gemini-driven autonomous pentest agent.")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--mode-label", default="unspecified")
    parser.add_argument("--db-path", default="instance/securegate.db")
    args = parser.parse_args()

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit("Set GEMINI_API_KEY in your environment or .env file.")
    model = os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)

    store = AgentStore(Path(args.db_path))
    result = run_llm_agent(args.base_url, args.mode_label, api_key, model, store)
    print(result)


if __name__ == "__main__":
    main()
