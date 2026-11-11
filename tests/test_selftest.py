"""Backend self-test: /snare status must tell "nothing tripped" from "the trap isn't set here".

The live probe is run for real: the fake ``dispatch_tool`` executes the probe command in ``sh``
with the environment a backend would give it.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import snare  # noqa: E402
from snare import selftest  # noqa: E402
from test_snare import FakeCtx  # noqa: E402


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))


class ProbeCtx(FakeCtx):
    """A Hermes whose terminal tool really runs the command, like a backend that does (or does
    not) pass plugin session variables."""

    def __init__(self, root, config=None, *, passes_env=True, session=True, fail=None):
        super().__init__(root, config)
        self.passes_env, self.session, self.fail = passes_env, session, fail
        self.calls: list = []

    def dispatch_tool(self, tool_name, args, **kw):
        self.calls.append((tool_name, args, kw))
        if self.fail:
            raise self.fail
        child = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if self.session:
            child["HERMES_SESSION_ID"] = "sess-1"
        if self.passes_env and self.session and self.session_env:
            names, resolver = self.session_env
            child.update({k: v for k, v in resolver("sess-1").items() if v is not None})
        proc = subprocess.run(["sh", "-c", args["command"]], env=child, capture_output=True, text=True)
        return json.dumps({"output": proc.stdout, "exit_code": proc.returncode, "error": None})


def load(ctx):
    snare.register(ctx)
    return ctx.commands["snare"]


# --- startup check (no commands run) --------------------------------------------------------------
def test_startup_local_is_unverified_and_runs_nothing(tmp_path):
    c = ProbeCtx(tmp_path)
    snare.register(c)
    assert c.calls == []
    assert c.commands["snare"].__self__.selftest.state == selftest.UNVERIFIED


def test_startup_warns_on_docker(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    c = ProbeCtx(tmp_path, passes_env=False)
    with caplog.at_level(logging.WARNING, logger="snare"):
        cmd = load(c)
    assert "not active here" in caplog.text and "docker" in caplog.text
    out = cmd("status")
    assert "NOT active here" in out and "docker" in out and "Blocking is still on" in out
    assert c.calls == []  # status never spins up a remote backend by itself


def test_backend_read_from_config_yaml(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text("terminal:\n  backend: ssh\n")
    assert selftest.configured_backend() == ("ssh", "config.yaml")
    out = load(ProbeCtx(tmp_path))("status")
    assert "NOT active here" in out and "ssh" in out


def test_env_canaries_off(tmp_path):
    out = load(ProbeCtx(tmp_path, {"env_canaries": False}))("status")
    assert "Decoys: off" in out and "env_canaries" in out


def test_old_hermes_without_session_env(tmp_path):
    class Old(ProbeCtx):  # hasattr(ctx, "register_session_env") is False, as on an old Hermes
        @property
        def register_session_env(self):
            raise AttributeError("register_session_env")
    out = load(Old(tmp_path))("status")
    assert "NOT active here" in out and "no plugin session environment" in out


def test_registration_refused(tmp_path):
    class Clash(ProbeCtx):
        def register_session_env(self, names, resolver):
            raise ValueError("session env 'PROD_DATABASE_URL' is already registered by 'other'")
    out = load(Clash(tmp_path))("status")
    assert "NOT active here" in out and "already registered" in out


# --- live probe -------------------------------------------------------------------------------------
def test_status_on_local_proves_decoys_are_there(tmp_path):
    c = ProbeCtx(tmp_path)
    out = load(c)("status", session_id="sess-1")
    assert "Decoys: active on the local backend" in out and "saw 3 of them" in out
    assert len(c.calls) == 1 and c.calls[0][0] == "terminal"
    assert c.calls[0][2] == {"session_id": "sess-1"}
    # The probe reports names, never values.
    resolver = c.session_env[1]
    for value in resolver("sess-1").values():
        assert value not in c.calls[0][1]["command"]


def test_conclusive_probe_is_reused(tmp_path):
    c = ProbeCtx(tmp_path)
    cmd = load(c)
    cmd("status", session_id="sess-1")
    cmd("status", session_id="sess-1")
    assert len(c.calls) == 1
    cmd("selftest", session_id="sess-1")  # an explicit self-test always probes again
    assert len(c.calls) == 2


def test_local_backend_that_drops_the_decoys(tmp_path):
    out = load(ProbeCtx(tmp_path, passes_env=False))("status", session_id="sess-1")
    assert "NOT active here" in out and "found no decoys" in out


def test_probe_outside_a_session_stays_unverified(tmp_path):
    c = ProbeCtx(tmp_path, session=False)
    cmd = load(c)
    out = cmd("status")
    assert "not verified yet" in out and "outside a chat session" in out
    cmd("status")
    assert len(c.calls) == 2  # an inconclusive answer is not cached


def test_selftest_on_docker_confirms_inactive(tmp_path, monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    c = ProbeCtx(tmp_path, passes_env=False)
    out = load(c)("selftest", session_id="sess-1")
    assert "NOT active here" in out and "live probe confirmed" in out
    assert len(c.calls) == 1


def test_selftest_trusts_what_it_sees_over_the_config(tmp_path, monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "docker")  # e.g. a future Hermes that forwards plugin env
    out = load(ProbeCtx(tmp_path, passes_env=True))("selftest", session_id="sess-1")
    assert "Decoys: active on the docker backend" in out


def test_probe_that_errors_is_unverified(tmp_path):
    out = load(ProbeCtx(tmp_path, fail=RuntimeError("backend down")))("status", session_id="sess-1")
    assert "not verified yet" in out and "backend down" in out


def test_hermes_without_dispatch_tool(tmp_path):
    out = load(FakeCtx(tmp_path))("status", session_id="sess-1")
    assert "not verified yet" in out and "can't run a live probe" in out


def test_backend_change_after_startup(tmp_path, monkeypatch):
    c = ProbeCtx(tmp_path)
    cmd = load(c)
    assert "active on the local" in cmd("status", session_id="sess-1")
    monkeypatch.setenv("TERMINAL_ENV", "modal")
    assert "NOT active here" in cmd("status", session_id="sess-1")


# --- the probe itself -------------------------------------------------------------------------------
def test_probe_command_skips_unsafe_names():
    cmd = selftest.probe_command(["PROD_DATABASE_URL", "BAD;rm -rf /", "$(x)"])
    assert "PROD_DATABASE_URL" in cmd and "rm -rf" not in cmd and "$(x)" not in cmd


def test_parse_probe_failure_reports_the_error():
    seen, session, err = selftest.parse_probe(json.dumps({"output": "", "error": "timed out"}))
    assert seen is None and err == "timed out"
