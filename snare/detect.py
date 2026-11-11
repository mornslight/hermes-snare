"""Heuristics: spot injected instructions in what the agent reads, and exfiltration in what it does.

These only *label* content for the attack chain. The tripwire itself never depends on them: a
canary leaving the agent is blocked whether or not any pattern here matched.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Optional

# --- Injected-instruction markers (for attribution) -------------------------------------------
# (label, weight, pattern). Weight >= 2 on its own marks content as a likely injection.
_I = re.IGNORECASE
INJECTION_RULES: list[tuple[str, int, re.Pattern]] = [
    ("override", 3, re.compile(
        r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|all|your|system)\b[^.\n]{0,30}?"
        r"\b(?:instructions?|rules|prompts?|guidelines|directives)\b", _I)),
    ("role-hijack", 3, re.compile(
        r"\byou\s+are\s+now\b|\bnew\s+system\s+(?:prompt|instructions?)\b"
        r"|\b(?:system|admin|developer)\s+(?:override|notice|message)\s*:", _I)),
    ("addressed-to-agent", 2, re.compile(
        r"\b(?:AI|assistant|agent|LLM|language\s+model|coding\s+agent)s?\b[^.\n]{0,60}?"
        r"\b(?:must|should|needs?\s+to|is\s+required\s+to|are\s+required\s+to)\b", _I)),
    ("conceal-from-user", 3, re.compile(
        r"\bdo\s*n[o']?t\s+(?:tell|inform|mention|alert|notify)\b[^.\n]{0,30}?\b(?:the\s+)?user\b"
        r"|\bwithout\s+(?:telling|informing|asking|notifying)\b[^.\n]{0,20}?\buser\b"
        r"|\b(?:silently|quietly|secretly)\b", _I)),
    ("secret-seeking", 1, re.compile(
        r"\b(?:env(?:ironment)?\s+var(?:iable)?s?|api[\s_-]?keys?|credentials?|secrets?"
        r"|access[\s_-]?keys?|passwords?|private\s+keys?)\b|\$[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|URL)\b"
        r"|\.aws/credentials|\.env\b", _I)),
    ("exfil-request", 2, re.compile(
        r"\b(?:send|post|upload|forward|exfiltrate|transmit|submit|report|ping)\b[^\n]{0,80}?https?://"
        r"|\b(?:curl|wget)\b[^\n]{0,120}?https?://", _I)),
    ("hidden-text", 1, re.compile(
        r"<!--|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|[\u200b-\u200f\u2060\ufeff]", _I)),
]

_SNIPPET_MAX = 280
_LINE_NO = re.compile(r"(?m)^[ \t]*\d{1,7}\|")


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _sentence(text: str, start: int, end: int) -> str:
    """The sentence (or line) around a match, so the quote reads as the instruction itself."""
    left = max(text.rfind(". ", 0, start), text.rfind("\n", 0, start), text.rfind(">", 0, start))
    rights = [i for i in (text.find(". ", end), text.find("\n", end)) if i != -1]
    right = min(rights) + 1 if rights else len(text)
    return _collapse(text[left + 1:right])


def scan_injection(text: str) -> Optional[dict[str, Any]]:
    """Score ``text`` for injected instructions. Returns ``None`` when nothing matched."""
    if not text:
        return None
    # read_file returns numbered lines ("29|text"); drop the numbers so quotes read as the source.
    text = _LINE_NO.sub("", text[:200_000])
    score, labels, quotes = 0, [], []
    for label, weight, pattern in INJECTION_RULES:
        m = pattern.search(text)
        if not m:
            continue
        score += weight
        labels.append(label)
        if label not in ("hidden-text", "secret-seeking"):
            quotes.append((weight, m.start(), _sentence(text, m.start(), m.end())))
    if not labels:
        return None
    suspicious = score >= 3 and any(lbl not in ("secret-seeking", "hidden-text") for lbl in labels)
    # Quote the strongest instruction, then what it asked for (the exfiltration step) if separate.
    quotes.sort(key=lambda q: (-q[0], q[1]))
    picked: list[str] = []
    for _, _, sent in quotes:
        if sent and sent not in picked:
            picked.append(sent)
        if len(picked) == 2:
            break
    exfil = next((q[2] for q in quotes if "http" in q[2]), None)
    if exfil and exfil not in picked:
        picked = picked[:1] + [exfil]
    snippet = " ... ".join(picked)
    if len(snippet) > _SNIPPET_MAX:
        snippet = snippet[:_SNIPPET_MAX - 3].rstrip() + "..."
    return {"score": score, "labels": labels, "suspicious": suspicious, "snippet": snippet}


# --- Sources and destinations ---------------------------------------------------------------
_URL = re.compile(r"https?://[^\s\"'<>()\\]+", _I)
_SOURCE_KEYS = ("url", "urls", "path", "file_path", "query", "command", "code")


def urls_in(value: Any) -> list[str]:
    try:
        blob = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        blob = str(value)
    out: list[str] = []
    for u in _URL.findall(blob):
        u = u.rstrip(".,;:]}")
        if u not in out:
            out.append(u)
    return out


def host_of(url: str) -> str:
    m = re.match(r"https?://([^/:?#]+)", url, _I)
    return m.group(1).lower() if m else ""


def short(text: str, n: int = 120) -> str:
    text = _collapse(text)
    return text if len(text) <= n else text[: n - 3].rstrip() + "..."


def describe_source(tool_name: str, args: Any) -> str:
    """Where a tool result came from, in a few words: a URL, a path, or the command."""
    args = args if isinstance(args, dict) else {}
    urls = urls_in(args)
    if urls:
        return urls[0]
    for key in _SOURCE_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return short(val, 100)
        if isinstance(val, list) and val:
            return short(str(val[0]), 100)
    return tool_name


def describe_action(tool_name: str, args: Any) -> str:
    args = args if isinstance(args, dict) else {}
    for key in ("command", "code", "url", "path", "content", "text", "message"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return short(val, 160)
    try:
        return short(json.dumps(args, ensure_ascii=False), 160)
    except (TypeError, ValueError):
        return tool_name


def result_text(result: Any) -> str:
    """Tool results are JSON strings; pull out the human text so snippets read cleanly."""
    if not isinstance(result, str):
        try:
            result = json.dumps(result, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(result)
    try:
        parsed = json.loads(result)
    except (TypeError, ValueError):
        return result
    parts: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            for item in v.values():
                walk(item)
        elif isinstance(v, list):
            for item in v:
                walk(item)
    walk(parsed)
    return "\n".join(parts) if parts else result


# --- Exfiltration by reference --------------------------------------------------------------
# A hijacked agent rarely pastes the secret into the command: it pipes it. These catch a command
# that both reads the decoys (by name, or by dumping the whole environment) and talks to a network.
_CODE_TOOLS = {"terminal", "execute_code", "process", "browser_exec"}
_EGRESS = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|telnet|ssh)\b|/dev/(?:tcp|udp)/"
    r"|https?://|\brequests\.|\burllib\b|\bhttpx\b|\bfetch\s*\(|\baiohttp\b|\bsocket\.", _I)
_ENV_DUMP = re.compile(
    r"(?:^|[\s;&|(`$])(?:print)?env\s*(?=$|[|>;&)`])|/proc/(?:self|\d+)/environ|\bexport\s+-p\b"
    r"|\bos\.environ\b(?!\s*(?:\.get|\[))|\bprocess\.env\b(?!\.)|\bdeclare\s+-x\b")


def env_reference(command: str, names: Iterable[str]) -> Optional[str]:
    """Which decoy name (or a whole-environment dump) ``command`` reads, if any."""
    for name in names:
        if re.search(rf"\b{re.escape(name)}\b", command):
            return name
    if _ENV_DUMP.search(command):
        return "the whole environment"
    return None


_RUNNER = re.compile(
    r"(?:^|[\s;&|(])(?:bash|sh|zsh|dash|source|\.|python3?|node|deno|bun|ruby|perl)\s+(?:-\S+\s+)*([^\s;&|<>]+)"
    r"|(?:^|[\s;&|(])(\.{0,2}/[^\s;&|<>]+)")
_CD = re.compile(r"(?:^|[;&]\s*)cd\s+([^\s;&|]+)")
_SCRIPT_MAX = 64 * 1024


def _base_dir(args: dict, command: str) -> Optional[Path]:
    for key in ("workdir", "cwd"):
        if isinstance(args.get(key), str) and args[key]:
            return Path(args[key]).expanduser()
    try:  # the session's working directory, the documented way for plugins to find it
        from agent.runtime_cwd import resolve_agent_cwd
        base = Path(resolve_agent_cwd())
    except Exception:
        base = Path.cwd()
    m = _CD.search(command)
    return (base / Path(m.group(1)).expanduser()) if m else base


def scripts_run_by(command: str, args: dict) -> list[tuple[str, str]]:
    """Local script files a command executes (``bash setup.sh``, ``./install``), with their text.
    Read-only, at most 64 KB each, only files that exist; used to see what the command will do."""
    base = _base_dir(args, command)
    out: list[tuple[str, str]] = []
    for m in _RUNNER.finditer(command):
        raw = (m.group(1) or m.group(2) or "").strip("'\"")
        if not raw or raw.startswith("-") or "://" in raw or raw in (".", ".."):
            continue
        path = Path(raw).expanduser()
        if not path.is_absolute() and base is not None:
            path = base / path
        try:
            if path.is_file() and path.stat().st_size <= _SCRIPT_MAX:
                out.append((str(path), path.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    return out[:4]


def env_exfil(tool_name: str, args: Any, names: Iterable[str]) -> Optional[dict[str, str]]:
    """Detect ``curl ... $PROD_AWS_SECRET_ACCESS_KEY`` / ``env | curl ...`` shaped calls, including
    when they sit inside a local script the command runs."""
    if tool_name not in _CODE_TOOLS or not isinstance(args, dict):
        return None
    names = list(names)
    command = "\n".join(str(args[k]) for k in ("command", "code", "input") if isinstance(args.get(k), str))
    if not command:
        return None
    ref = env_reference(command, names)
    if ref and _EGRESS.search(command):
        return {"reads": ref, "command": command}
    if tool_name in ("terminal", "process"):
        for path, text in scripts_run_by(command, args):
            ref = env_reference(text, names)
            if ref and _EGRESS.search(text):
                return {"reads": ref, "command": command, "script": path, "urls": urls_in(text)}
    return None
