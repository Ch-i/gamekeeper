"""Local LLM seam — a locally-authenticated CLI, never an API key.

gamekeeper only ever talks to a model through a CLI that is already signed in on this
machine: the `claude` CLI (Claude Code), the `codex` CLI, or — if installed alongside —
saddlerFitter's harness (which itself wraps those local CLIs). No API keys are read,
stored, or sent. Every call is logged to the store (prompt + response) so you can see
exactly what was asked and answered in the dashboard.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def which() -> dict:
    """Which locally-authenticated CLI will be used, for display + transparency."""
    if shutil.which("claude"):
        return {"source": "claude", "detail": "claude CLI — local, no API keys",
                "bin": shutil.which("claude")}
    if shutil.which("codex"):
        return {"source": "codex", "detail": "codex CLI — local, no API keys",
                "bin": shutil.which("codex")}
    try:
        import saddlerfitter.llm  # noqa: F401
        return {"source": "saddlerfitter", "detail": "saddlerFitter harness (local CLIs)"}
    except Exception:
        return {"source": "none", "detail": "no local LLM CLI found"}


def available() -> str:
    return which()["source"] if which()["source"] != "none" else ""


def _call(prompt: str, model: str, timeout: int) -> tuple[str | None, str]:
    """Returns (response, source). Tries claude, then codex, then saddlerFitter."""
    claude = shutil.which("claude")
    if claude:
        try:
            r = subprocess.run([claude, "-p", prompt, "--output-format", "text"],
                               capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip(), "claude"
        except Exception:
            pass
    codex = shutil.which("codex")
    if codex:
        try:
            r = subprocess.run([codex, "exec", "--skip-git-repo-check", prompt],
                               capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip(), "codex"
        except Exception:
            pass
    try:
        from saddlerfitter.llm import run_agent  # type: ignore
        out = run_agent(prompt, model=model)
        if out:
            return out, "saddlerfitter"
    except Exception:
        pass
    return None, "none"


def run(prompt: str, model: str = "sonnet", timeout: int = 120,
        store=None, purpose: str = "") -> str | None:
    """Call the local CLI and (if a store is given) log the prompt + response."""
    resp, source = _call(prompt, model, timeout)
    if store is not None:
        try:
            store.add_llm_call(purpose, model, source, prompt, resp or "", bool(resp), _now())
        except Exception:
            pass
    return resp
