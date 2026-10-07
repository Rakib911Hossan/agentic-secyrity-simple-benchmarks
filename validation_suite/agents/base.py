"""Base class for specialized validation agents.

Each agent owns exactly one vulnerability class and follows the same
recon -> scan -> exploit -> result loop used throughout this project
(mirrors the staged workflow described in Agent_solves_benchmark_problems.pdf,
scoped down to a fixed, known set of checks against this app's own
localhost instance — no open-ended target discovery).

A Coordinator (validation_suite/runner.py) instantiates one agent per
vulnerability class and runs them concurrently, so "multiple agents
working" is literal, not just a figure of speech: each agent has its own
HTTP session/state and does not share mutable state with the others.
"""
from validation_suite.checks.common import CheckResult


class Agent:
    name = "agent"

    def __init__(self):
        self.steps: list[dict] = []

    def log(self, stage: str, message: str):
        """Records one step of this agent's reasoning for the report.
        stage is one of: recon, scan, exploit, result."""
        self.steps.append({"stage": stage, "message": message})

    def run(self, base_url: str) -> CheckResult:
        """Subclasses implement recon/scan/exploit via self.log(...) calls
        and return a CheckResult carrying self.steps."""
        raise NotImplementedError

    def result(self, passed: bool, detail: str) -> CheckResult:
        self.log("result", detail)
        return CheckResult(self.name, passed, detail, steps=self.steps)
