/* Polls the AI pentest agent's transcript endpoint and renders it as an
 * organized timeline: one card per tool call (stage badge + the agent's own
 * stated reasoning + the request/response that followed), rather than a
 * flat log. Lives in its own file so the page still satisfies the
 * secure-mode CSP (script-src 'self', no inline). */
(function () {
  const params = new URLSearchParams(window.location.search);
  const runId = params.get("run_id");
  if (!runId) return;

  const section = document.getElementById("transcript-section");
  const list = document.getElementById("transcript");
  const statusEl = document.getElementById("run-status");
  const progressBar = document.getElementById("progress-bar");
  const maxSteps = parseInt(section.dataset.maxSteps || "0", 10) || 1;
  section.style.display = "block";
  // Bring the live transcript into view — on a fresh run or when the user
  // clicks "view" on a past run (which reloads the page at the top).
  section.scrollIntoView({ behavior: "smooth", block: "start" });

  let shown = 0;
  let currentCard = null;
  let currentStepNum = 0;

  const STEP_RE = /^\[step (\d+)\] (\w+): ?(.*)$/s;
  const RESULT_RE = /^ {2}-> (.*)$/s;
  const RETRY_RE = /^\(Gemini API transient error/;

  function stageLabel(stage) {
    return (stage || "exploit").toLowerCase();
  }

  function newCard(stepNum, stage, tool, reasoning) {
    const card = document.createElement("article");
    card.className = "agent-step";

    const head = document.createElement("div");
    head.className = "agent-step-head";

    const badge = document.createElement("span");
    badge.className = `stage-pill stage-${stageLabel(stage)}`;
    badge.textContent = stage;
    head.appendChild(badge);

    const title = document.createElement("span");
    title.className = "agent-step-title";
    title.textContent = `step ${stepNum} · ${tool}`;
    head.appendChild(title);

    card.appendChild(head);

    if (reasoning) {
      const p = document.createElement("p");
      p.className = "agent-step-reasoning";
      p.textContent = reasoning;
      card.appendChild(p);
    }

    list.appendChild(card);
    return card;
  }

  function addResult(card, text) {
    const pre = document.createElement("pre");
    pre.className = "agent-step-result";
    pre.textContent = text;
    (card || list).appendChild(pre);
  }

  function addNote(text, kind) {
    const p = document.createElement("p");
    p.className = `agent-note ${kind || ""}`;
    p.textContent = text;
    list.appendChild(p);
  }

  function renderStep(s) {
    const msg = s.message;

    const stepMatch = msg.match(STEP_RE);
    if (stepMatch) {
      currentStepNum = parseInt(stepMatch[1], 10);
      currentCard = newCard(currentStepNum, s.stage, stepMatch[2], stepMatch[3]);
      progressBar.style.width = `${Math.min(100, (currentStepNum / maxSteps) * 100)}%`;
      return;
    }

    const resultMatch = msg.match(RESULT_RE);
    if (resultMatch) {
      addResult(currentCard, resultMatch[1]);
      return;
    }

    if (RETRY_RE.test(msg)) {
      addNote(msg, "retry");
      return;
    }

    // A plain {stage, message} step — either free-form LLM text, or a step
    // from a scripted agent (which has no "[step N]" prefix). Render it as a
    // simple stage-badged card.
    const wrap = document.createElement("article");
    wrap.className = "agent-step";
    const head = document.createElement("div");
    head.className = "agent-step-head";
    const pill = document.createElement("span");
    pill.className = `stage-pill stage-${stageLabel(s.stage)}`;
    pill.textContent = s.stage;
    head.appendChild(pill);
    wrap.appendChild(head);
    const p = document.createElement("p");
    p.className = "agent-step-reasoning";
    p.textContent = msg;
    wrap.appendChild(p);
    list.appendChild(wrap);
    currentCard = null;
  }

  function poll() {
    fetch(`/admin/agent/status/${runId}`)
      .then((r) => r.json())
      .then((data) => {
        if (data.error) { statusEl.textContent = "Run not found."; return; }
        for (let i = shown; i < data.steps.length; i++) renderStep(data.steps[i]);
        shown = data.steps.length;

        if (data.status === "running") {
          statusEl.textContent = `Running… step ${currentStepNum || 0} of ${maxSteps}`;
          setTimeout(poll, 1500);
        } else {
          progressBar.style.width = "100%";
          const labels = {
            captured: "Flag captured — exploit succeeded.",
            breached: "Weakness found — the attack landed (defense was down).",
            failed: "Agent did not succeed.",
            defended: "Attack blocked — the defense held.",
            remediated: "Breach → Fix → Verify complete: exploited in vulnerable mode, blocked after the fix.",
            contained: "Prompt injection contained — the agent never obtained the real flag.",
            unverified: "Agent claimed success but the flag didn't match — treat as not captured.",
          };
          // Good (green) outcomes: defense held, remediation proven, injection contained.
          const goodOutcome = ["defended", "remediated", "contained"].includes(data.status);
          const label = labels[data.status] || data.status;
          statusEl.textContent = "";
          const strong = document.createElement("strong");
          strong.className = goodOutcome ? "ok" : "fail";
          strong.textContent = label;
          statusEl.appendChild(strong);
          progressBar.classList.add(goodOutcome ? "ok" : "fail");
        }
      })
      .catch(() => { setTimeout(poll, 2500); });
  }
  poll();
})();
