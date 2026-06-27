"""Local LLM seam — pairs with saddlerFitter, else the local `claude` CLI.

No API keys: gamekeeper reuses whatever locally-authenticated model is already on the box.
If saddlerFitter is installed alongside, we borrow its harness; otherwise we shell the
`claude` CLI; if neither is present, callers fall back to their heuristics.
"""
from __future__ import annotations

import shutil
import subprocess


def available() -> str:
    try:
        import saddlerfitter.llm  # noqa: F401
        return "saddlerfitter"
    except Exception:
        pass
    return "claude" if shutil.which("claude") else ""


def run(prompt: str, model: str = "sonnet", timeout: int = 120) -> str | None:
    try:
        from saddlerfitter.llm import run_agent  # type: ignore
        return run_agent(prompt, model=model)
    except Exception:
        pass
    claude = shutil.which("claude")
    if claude:
        try:
            r = subprocess.run([claude, "-p", prompt, "--output-format", "text"],
                               capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
    return None
