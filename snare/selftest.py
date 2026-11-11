"""Backend self-test: do the decoys actually reach the commands the agent runs?

Hermes gives plugin session variables (``ctx.register_session_env``) to commands on the **local**
terminal backend only. On Docker, SSH, Modal and other remote backends the decoys never appear, so
"no incidents" there can mean "nothing tripped" or "the trap is not set here". This module tells
the two apart:

* ``static_check`` runs at startup with no side effects: is the env trap enabled, did the
  registration succeed, and which terminal backend is configured.
* ``live_probe`` runs one harmless command through Hermes's own terminal tool
  (``ctx.dispatch_tool``), so it goes to whatever backend is really active, and reports which
  decoy names the command saw. It prints names only, never values.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

ACTIVE = "active"            # a live probe saw the decoys in a command's environment
INACTIVE = "inactive"        # the decoys do not reach commands on this backend
UNVERIFIED = "unverified"    # expected to work, not proven yet
OFF = "off"                  # turned off in settings, or nothing to plant

_MARK = "snare-probe"
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class Result:
    state: str
    backend: str = "local"
    backend_source: str = "default"
    detail: str = ""
    live: bool = False                       # True when a probe ran, False for the startup check
    seen: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    def line(self) -> str:
        """One line for ``/snare status``."""
        when = time.strftime("%H:%M", time.localtime(self.ts))
        if self.state == ACTIVE:
            return (f"Decoys: active on the {self.backend} backend "
                    f"(live check at {when} saw {len(self.seen)} of them in a command's environment).")
        if self.state == INACTIVE:
            return (f"Decoys: NOT active here. {self.detail} Blocking is still on: a decoy or a "
                    "decoy-reading command in a tool call is still stopped, but a hijacked agent "
                    "won't find decoys in this backend's environment, so the trap rarely fires.")
        if self.state == OFF:
            return f"Decoys: off. {self.detail}"
        return f"Decoys: not verified yet. {self.detail}"


def configured_backend(home: Optional[Path] = None) -> tuple[str, str]:
    """The terminal backend Hermes will use, and where that answer came from."""
    try:  # the per-turn terminal scope Hermes's own tools read (multi-profile gateways)
        from tools.terminal_scope import terminal_env  # type: ignore
        value = (terminal_env("TERMINAL_ENV") or "").strip().lower()
        if value:
            return value, "Hermes terminal settings"
    except Exception:
        pass
    value = (os.environ.get("TERMINAL_ENV") or "").strip().lower()
    if value:
        return value, "TERMINAL_ENV"
    home = home or Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
    try:
        import yaml  # Hermes depends on PyYAML; snare itself does not
        cfg = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8")) or {}
        value = str(((cfg.get("terminal") or {}).get("backend") or "")).strip().lower()
        if value:
            return value, "config.yaml"
    except Exception:
        pass
    return "local", "default"


def static_check(*, enabled: bool, names: Iterable[str], registered: Optional[bool],
                 reg_error: str = "", home: Optional[Path] = None) -> Result:
    """The startup self-test. ``registered`` is None when this Hermes has no session env API."""
    backend, source = configured_backend(home)
    names = list(names)
    if not enabled:
        return Result(OFF, backend, source, "env_canaries is set to false.")
    if not names:
        return Result(OFF, backend, source, "Every decoy name is already set in your environment, "
                                            "so none were planted.")
    if registered is None:
        return Result(INACTIVE, backend, source,
                      "This Hermes version has no plugin session environment, so decoys can't be planted.")
    if not registered:
        return Result(INACTIVE, backend, source, f"Hermes refused the decoy variables ({reg_error}).")
    if backend != "local":
        return Result(INACTIVE, backend, source,
                      f"The terminal backend is {backend} ({source}), and Hermes only passes plugin "
                      "session variables to the local backend.")
    return Result(UNVERIFIED, backend, source,
                  "The backend is local, so the decoys should be there. "
                  "Run /snare selftest in a chat to prove it.")


def probe_command(names: Iterable[str]) -> str:
    """A POSIX sh one-liner that prints which decoy names a command sees, never their values."""
    parts = []
    for n in names:
        if not _NAME_RE.fullmatch(n):
            continue
        parts.append(f'case "${{{n}-}}" in *snare*|*SNARE*) echo "{_MARK} {n}";; esac')
    parts.append(f'echo "{_MARK}-session ${{HERMES_SESSION_ID:+yes}}"')
    parts.append(f'echo "{_MARK}-done"')
    return "; ".join(parts)


def parse_probe(raw: Any) -> tuple[Optional[list[str]], Optional[bool], str]:
    """(names seen or None if the probe didn't run, whether the command knew its session, error)."""
    text = raw if isinstance(raw, str) else json.dumps(raw) if raw is not None else ""
    data: Any = None
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        pass
    if isinstance(data, dict):
        out = str(data.get("output") or "")
        err = str(data.get("error") or "")
    else:
        out, err = text, ""
    if f"{_MARK}-done" not in out:
        reason = err or (out.strip().splitlines() or ["no output"])[0]
        return None, None, reason[:160]
    seen, session = [], False
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(f"{_MARK}-session"):
            session = line.endswith("yes")
        elif line.startswith(f"{_MARK} "):
            seen.append(line.split(" ", 1)[1])
    return seen, session, ""


def live_probe(ctx: Any, names: list[str], base: Result, **call_kw: Any) -> Result:
    """Run the probe through Hermes's active terminal backend and judge the answer."""
    backend, source = base.backend, base.backend_source
    if base.state == OFF:
        return base
    dispatch = getattr(ctx, "dispatch_tool", None)
    if not callable(dispatch):
        note = "This Hermes can't run a live probe from a plugin, so this is from its settings only."
        return Result(base.state, backend, source, f"{base.detail} {note}".strip())
    kw = {k: v for k, v in call_kw.items() if k in ("task_id", "session_id") and v}
    try:
        raw = dispatch("terminal", {"command": probe_command(names), "timeout": 20}, **kw)
    except Exception as exc:
        return Result(UNVERIFIED, backend, source, f"The probe couldn't run ({type(exc).__name__}: {exc}).")
    seen, session, err = parse_probe(raw)
    if seen is None:
        return Result(UNVERIFIED, backend, source, f"The probe couldn't run ({err}).")
    if seen:
        return Result(ACTIVE, backend, source, live=True, seen=seen)
    if base.state == INACTIVE:  # already known why; the probe only confirms it
        return Result(INACTIVE, backend, source, f"{base.detail} A live probe confirmed it.", live=True)
    if session or backend != "local":
        why = (f"A live probe on the {backend} backend found no decoys in a command's environment."
               + (" Hermes only passes plugin session variables to the local backend." if backend != "local"
                  else " Hermes may be filtering them out."))
        return Result(INACTIVE, backend, source, why, live=True)
    return Result(UNVERIFIED, backend, source,
                  "The probe ran outside a chat session, so Hermes had no session to give decoys to. "
                  "Run /snare selftest from a chat.", live=True)
