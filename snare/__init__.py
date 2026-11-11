"""snare: a prompt injection tripwire for Hermes Agent.

It plants decoy credentials where a hijacked agent goes looking (the environment of every command
the agent runs), blocks any tool call that tries to send one out, and explains the attack chain:
which content the injected instruction came from, what it said, how the decoy was exposed and
what the agent tried to do with it.

Hooks: ``post_tool_call`` (ledger of what the agent read), ``pre_tool_call`` (the tripwire),
``transform_llm_output`` (the user-facing alert and redaction). Session env: the decoys.
Slash command: ``/snare``.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Optional

from . import canaries as _canaries
from . import chain as _chain
from . import detect as _detect
from . import report as _report
from . import selftest as _selftest

logger = logging.getLogger(__name__)

PLUGIN_ID = "snare"
_STATE_KEY = "canaries"
_PENDING_TTL_S = 10 * 60
# Tools whose results are the agent's own writes, not content it read from somewhere.
_NOT_READS = {"write_file", "patch", "todo", "clarify", "memory", "skill_manage", "send_message"}


def _keys(**kw: Any) -> list[str]:
    keys = [str(kw.get(k)) for k in ("session_id", "task_id") if kw.get(k)]
    return keys or ["default"]


class Snare:
    def __init__(self, ctx: Any = None) -> None:
        self.ctx = ctx
        self.ledger = _chain.Ledger()
        self._lock = threading.Lock()
        self._locked: set[str] = set()
        self._pending: dict[str, dict[str, Any]] = {}
        self.profile = getattr(ctx, "profile_name", "") or "default"
        self.lockdown = bool(self._cfg("lockdown", True))
        self.block_env_exfil = bool(self._cfg("block_env_exfil", True))
        self.canaries = self._load_canaries()
        self.matcher = _canaries.Matcher(self.canaries)
        self.env_names = self._plantable_names()
        # Startup self-test result (set by register()), replaced by a live probe when one runs.
        self.selftest: Optional[_selftest.Result] = None
        self._registered: Optional[bool] = True if ctx is not None else None
        self._reg_error = ""

    # --- setup ---------------------------------------------------------------------------
    def _cfg(self, key: str, default: Any) -> Any:
        try:
            return self.ctx.get_config(key, default) if self.ctx is not None else default
        except Exception:
            return default

    @property
    def data_dir(self) -> Path:
        state = getattr(self.ctx, "state", None)
        path = getattr(state, "data_dir", None)
        if path:
            return Path(path)
        home = os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes")
        return Path(home) / "plugin-data" / PLUGIN_ID

    def _load_canaries(self) -> dict[str, dict[str, str]]:
        state = getattr(self.ctx, "state", None)
        stored = None
        try:
            stored = state.get(_STATE_KEY) if state is not None else None
        except Exception as exc:
            logger.warning("snare: cannot read state (%s); using session-only decoys", exc)
        if isinstance(stored, dict) and all(isinstance(v, dict) and v.get("core") for v in stored.values()):
            return stored
        fresh = _canaries.generate()
        self._save_canaries(fresh)
        return fresh

    def _save_canaries(self, value: dict[str, dict[str, str]]) -> None:
        state = getattr(self.ctx, "state", None)
        try:
            if state is not None:
                state.set(_STATE_KEY, value)
        except Exception as exc:
            logger.warning("snare: cannot save decoys (%s)", exc)

    def _plantable_names(self) -> list[str]:
        # Never shadow a variable the user really has set, whatever its name.
        return [n for n in self.canaries if os.environ.get(n) is None]

    def rotate(self) -> None:
        with self._lock:
            self.canaries = _canaries.generate()
            self.matcher = _canaries.Matcher(self.canaries)
            self._save_canaries(self.canaries)

    # --- session env ------------------------------------------------------------------------
    def session_env(self, session_id: str) -> dict[str, Optional[str]]:
        if not bool(self._cfg("env_canaries", True)):
            return {}
        return {n: self.canaries[n]["value"] for n in self.env_names if n in self.canaries}

    # --- hooks ---------------------------------------------------------------------------------
    def on_post_tool_call(self, tool_name: str = "", args: Any = None, result: Any = "", **kw: Any) -> None:
        try:
            keys = _keys(**kw)
            text = _detect.result_text(result)
            hit = self.matcher.find_in_text(text)
            if hit:
                for k in keys:
                    self.ledger.add_exposure(_chain.Exposure(
                        time.time(), k, tool_name, _detect.describe_action(tool_name, args), hit.name))
            if tool_name in _NOT_READS:
                return
            scan = _detect.scan_injection(text) or {}
            for k in keys:
                self.ledger.add_ingest(_chain.Ingest(
                    ts=time.time(), session=k, tool=tool_name,
                    source=_detect.describe_source(tool_name, args),
                    suspicious=bool(scan.get("suspicious")), score=int(scan.get("score", 0)),
                    labels=list(scan.get("labels", [])), snippet=scan.get("snippet", "")))
        except Exception as exc:  # an observer must never break the agent
            logger.debug("snare post_tool_call error: %s", exc)

    def on_pre_tool_call(self, tool_name: str = "", args: Any = None, **kw: Any) -> Optional[dict[str, Any]]:
        keys = _keys(**kw)
        try:
            hit = self.matcher.find(args)
            if hit:
                return self._trip(keys, tool_name, args, leaked=hit.name, encoding=hit.encoding, kind="canary")
            if self.block_env_exfil:
                ref = _detect.env_exfil(tool_name, args, self.env_names or list(self.canaries))
                if ref:
                    how = f"by reference, inside {ref['script']}" if ref.get("script") else "by reference"
                    return self._trip(keys, tool_name, args, leaked=ref["reads"], encoding=how,
                                      kind="env-reference", destinations=ref.get("urls"))
        except Exception as exc:
            # A bug in snare must not stop the agent: log it and let the call through.
            logger.warning("snare pre_tool_call error: %s", exc)
            return None
        if self.lockdown and any(k in self._locked for k in keys):
            return {"action": "approve", "rule_key": "snare:lockdown",
                    "message": "Snare blocked a prompt injection in this session. "
                               f"Approve this {tool_name} call only if you asked for it."}
        return None

    def on_transform_llm_output(self, response_text: str = "", session_id: str = "", **kw: Any) -> Optional[str]:
        try:
            text = response_text or ""
            redacted = self.matcher.redact(text)
            alert = self._take_pending(_keys(session_id=session_id, **kw))
            if alert is None and redacted == text:
                return None
            return f"{alert}\n\n---\n\n{redacted}" if alert else redacted
        except Exception as exc:
            logger.debug("snare transform_llm_output error: %s", exc)
            return None

    # --- incidents ---------------------------------------------------------------------------
    def _trip(self, keys: list[str], tool_name: str, args: Any, *, leaked: str, encoding: str,
              kind: str, destinations: Optional[list[str]] = None) -> dict[str, str]:
        chain = _chain.build_chain(
            self.ledger, keys, tool=tool_name, action=_detect.describe_action(tool_name, args),
            leaked=leaked, encoding=encoding, destinations=destinations or _detect.urls_in(args), kind=kind)
        incident = {
            "id": time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2),
            "ts": time.time(), "session": keys[0], "profile": self.profile, "chain": chain,
        }
        try:
            _report.write_incident(self.data_dir, incident)
        except OSError as exc:
            logger.warning("snare: could not write incident report: %s", exc)
        with self._lock:
            if self.lockdown:
                self._locked.update(keys)
            entry = next((self._pending[k] for k in keys if k in self._pending), None)
            if entry is None:
                entry = {"text": _report.alert_text(incident, locked=self.lockdown), "ts": time.time(), "more": []}
            else:  # several blocked attempts in one turn: one alert, the rest listed under it
                att = incident["chain"]["attempt"]
                enc = "" if att["encoding"] in ("plain", "") else f" ({att['encoding']})"
                entry["more"].append(f"`{att['tool']}` {att['leaked']}{enc}: `{att['action']}`")
            for k in keys:
                self._pending[k] = entry
        logger.warning("snare: blocked %s leaking %s (incident %s)", tool_name, leaked, incident["id"])
        return {"action": "block", "message": _report.model_message(incident)}

    def _take_pending(self, keys: list[str]) -> Optional[str]:
        with self._lock:
            entry = None
            for k in keys:
                entry = entry or self._pending.get(k)
            if entry is None:  # ids differ across hook surfaces: take a fresh unmatched alert
                fresh = [e for e in self._pending.values() if time.time() - e["ts"] < _PENDING_TTL_S]
                entry = fresh[-1] if fresh else None
            if entry is None:
                return None
            for k in [k for k, v in self._pending.items() if v is entry]:
                del self._pending[k]
            text = entry["text"]
            if entry.get("more"):
                text += f"\n\nAlso blocked in this turn ({len(entry['more'])}):\n" + "\n".join(
                    f"- {m}" for m in entry["more"])
            return text

    # --- backend self-test ---------------------------------------------------------------------
    def _static_check(self) -> _selftest.Result:
        return _selftest.static_check(
            enabled=bool(self._cfg("env_canaries", True)), names=self.env_names,
            registered=self._registered, reg_error=self._reg_error)

    def startup_selftest(self, registered: Optional[bool], error: str = "") -> _selftest.Result:
        """Config-only check at load time (no commands run). Warns when the env trap is not set."""
        self._registered, self._reg_error = registered, error
        self.selftest = self._static_check()
        if self.selftest.state == _selftest.INACTIVE:
            logger.warning("snare: decoys are not active here: %s", self.selftest.detail)
        else:
            logger.info("snare: startup self-test: %s", self.selftest.line())
        return self.selftest

    def backend_check(self, force: bool = False, **kw: Any) -> _selftest.Result:
        """The current answer for ``/snare status``. A conclusive live probe is reused while the
        backend stays the same; on the local backend an unproven answer gets a live probe by
        itself; ``force`` (``/snare selftest``) probes whatever the backend is."""
        static = self._static_check()
        prev = self.selftest
        if static.state == _selftest.OFF:
            result = static
        elif (not force and prev is not None and prev.live and prev.backend == static.backend
              and prev.state in (_selftest.ACTIVE, _selftest.INACTIVE)):
            result = prev
        elif force or static.state == _selftest.UNVERIFIED:
            result = _selftest.live_probe(self.ctx, list(self.env_names), static, **kw)
        else:
            result = static
        self.selftest = result
        return result

    # --- /snare ------------------------------------------------------------------------------
    def command(self, raw_args: str = "", session_id: str = "", **kw: Any) -> str:
        parts = (raw_args or "").strip().split(None, 1)
        sub = parts[0].lower() if parts else "status"
        rest = parts[1] if len(parts) > 1 else ""
        if sub == "status":
            check = self.backend_check(session_id=session_id, **kw)
            incidents = _report.read_incidents(self.data_dir, 1000)
            planted = ", ".join(self.env_names) or "none (names already set in your environment)"
            return (f"Snare is on. Decoy names: {planted}.\n"
                    f"{check.line()}\n"
                    f"Incidents so far: {len(incidents)}. Locked sessions: {len(self._locked)}. "
                    f"Lockdown after a trip: {'on' if self.lockdown else 'off'}.\n"
                    f"Audit log: {self.data_dir / 'incidents.jsonl'}")
        if sub in ("selftest", "check"):
            return self.backend_check(force=True, session_id=session_id, **kw).line()
        if sub in ("incidents", "log"):
            rows = _report.read_incidents(self.data_dir, 10)
            if not rows:
                return "No incidents yet."
            out = []
            for r in rows:
                att = r["chain"]["attempt"]
                src = (r["chain"].get("source") or {}).get("source", "unknown source")
                out.append(f"{r['id']}  {att['tool']} -> {att['leaked']}  from {src}")
            return "\n".join(out)
        if sub in ("last", "report"):
            rows = _report.read_incidents(self.data_dir, 50)
            if rest:
                rows = [r for r in rows if r["id"].startswith(rest.strip())]
            if not rows:
                return "No incidents yet."
            return _report.alert_text(rows[-1], locked=False)
        if sub == "reset":
            keys = _keys(session_id=session_id, **kw)
            with self._lock:
                if rest.strip() == "all":
                    self._locked.clear()
                else:
                    self._locked.difference_update(keys)
                    if keys == ["default"]:
                        self._locked.clear()
            return "Snare lockdown cleared. The tripwire stays armed."
        if sub == "rotate":
            self.rotate()
            return "New decoys generated. Commands started from now on get the new values."
        if sub == "test":
            hit = self.matcher.find_in_text(rest)
            scan = _detect.scan_injection(rest)
            parts_out = [f"decoy: {hit.describe()}" if hit else "decoy: none"]
            parts_out.append(f"injection markers: {', '.join(scan['labels'])} (score {scan['score']})"
                             if scan else "injection markers: none")
            return "\n".join(parts_out)
        return "Usage: /snare [status|selftest|incidents|last|report <id>|reset [all]|rotate|test <text>]"


def register(ctx: Any) -> None:
    snare = Snare(ctx)
    ctx.register_hook("post_tool_call", snare.on_post_tool_call)
    ctx.register_hook("pre_tool_call", snare.on_pre_tool_call)
    ctx.register_hook("transform_llm_output", snare.on_transform_llm_output)
    registered: Optional[bool] = None
    error = ""
    if hasattr(ctx, "register_session_env"):
        registered = False
        if snare.env_names:
            try:
                ctx.register_session_env(list(snare.env_names), snare.session_env)
                registered = True
            except (ValueError, TypeError) as exc:
                error = str(exc)
                logger.warning("snare: decoys not planted in the environment: %s", exc)
    snare.startup_selftest(registered, error)
    if hasattr(ctx, "register_command"):
        ctx.register_command("snare", snare.command,
                             description="Prompt injection tripwire: status, incidents, reset, rotate")
