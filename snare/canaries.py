"""Decoy credentials (canaries) and the matcher that spots them, however they are disguised.

Every value here is fake and grants nothing. Each one carries the marker ``snare`` so a human who
finds it in a log knows at once what it is, while still having the shape an attacker's injected
instructions look for (an AWS key pair, a database URL).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import string
from dataclasses import dataclass
from typing import Any, Iterable, Optional
from urllib.parse import quote, unquote

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B62 = string.ascii_letters + string.digits

# Names a real SDK or tool would never read, so planting them cannot shadow a real credential.
DEFAULT_ENV_NAMES = (
    "PROD_AWS_ACCESS_KEY_ID",
    "PROD_AWS_SECRET_ACCESS_KEY",
    "PROD_DATABASE_URL",
)

# Shortest stretch of a canary's random core that still counts as a leak (partial copies).
FRAGMENT_LEN = 12


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def generate() -> dict[str, dict[str, str]]:
    """A fresh canary set: ``{env_name: {"value": full value, "core": distinctive token}}``."""
    key_core = "SNARE" + _rand(_B32, 11)
    secret_core = "snare" + _rand(_B62, 35)
    db_core = "snare" + _rand(_B62, 19)
    return {
        "PROD_AWS_ACCESS_KEY_ID": {"value": "AKIA" + key_core, "core": key_core},
        "PROD_AWS_SECRET_ACCESS_KEY": {"value": secret_core, "core": secret_core},
        "PROD_DATABASE_URL": {
            "value": f"postgres://admin:{db_core}@db.prod.internal:5432/app",
            "core": db_core,
        },
    }


@dataclass
class Hit:
    name: str          # env name of the canary that leaked
    encoding: str      # plain, url-encoded, base64, hex, reversed, fragment
    where: str = ""    # argument path the leak was found in

    def describe(self) -> str:
        how = "" if self.encoding == "plain" else f" ({self.encoding})"
        return f"{self.name}{how}"


def _flatten(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    """Every string leaf of a nested tool-argument structure, with its dotted path."""
    if isinstance(value, str):
        yield path or "args", value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            yield from _flatten(item, f"{path}[{i}]")
    elif value is not None:
        yield path or "args", str(value)


_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def _decoded_views(text: str) -> Iterable[tuple[str, str]]:
    """Alternative readings of ``text`` an exfiltration might hide a canary in."""
    if "%" in text:
        yield "url-encoded", unquote(text)
    yield "reversed", text[::-1]
    for run in _B64_RUN.findall(text):
        padded = run + "=" * (-len(run) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                yield "base64", decoder(padded).decode("utf-8", "ignore")
                break
            except (binascii.Error, ValueError):
                continue
    for run in _HEX_RUN.findall(text):
        try:
            yield "hex", bytes.fromhex(run).decode("utf-8", "ignore")
        except ValueError:
            continue


class Matcher:
    """Finds any canary in a string or nested structure."""

    def __init__(self, canaries: dict[str, dict[str, str]]):
        self.canaries = canaries
        self._cores = {name: c["core"] for name, c in canaries.items() if c.get("core")}
        self._fragments: list[tuple[str, str]] = []
        for name, core in self._cores.items():
            # Skip the fixed "snare"/"SNARE" prefix so fragments stay random enough to be unique.
            body = core[5:] if core.lower().startswith("snare") else core
            for i in range(0, max(0, len(body) - FRAGMENT_LEN) + 1):
                self._fragments.append((name, body[i:i + FRAGMENT_LEN]))

    def _plain(self, text: str) -> Optional[str]:
        for name, core in self._cores.items():
            if core in text:
                return name
        return None

    def find_in_text(self, text: str) -> Optional[Hit]:
        if not text:
            return None
        name = self._plain(text)
        if name:
            return Hit(name, "plain")
        # Encoded copies of the whole core are checked before fragments (more specific).
        for name, core in self._cores.items():
            for label, encoded in (("url-encoded", quote(core, safe="")),
                                   ("hex", core.encode().hex())):
                if encoded != core and encoded in text:
                    return Hit(name, label)
        for label, view in _decoded_views(text):
            name = self._plain(view)
            if name:
                return Hit(name, label)
        for name, frag in self._fragments:
            if frag in text:
                return Hit(name, "fragment")
        return None

    def find(self, value: Any) -> Optional[Hit]:
        if isinstance(value, (dict, list, tuple)):
            for path, leaf in _flatten(value):
                hit = self.find_in_text(leaf)
                if hit:
                    hit.where = path
                    return hit
            # A canary split across keys would still show up in the serialized form.
            try:
                return self.find_in_text(json.dumps(value, ensure_ascii=False))
            except (TypeError, ValueError):
                return None
        return self.find_in_text(str(value) if value is not None else "")

    def redact(self, text: str) -> str:
        for name, c in self.canaries.items():
            for token in {c.get("value", ""), c.get("core", "")}:
                if token:
                    text = text.replace(token, f"[decoy {name} redacted by snare]")
        return text
