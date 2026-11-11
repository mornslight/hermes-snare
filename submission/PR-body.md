## What does this PR do?

Adds one catalog entry, `plugin-catalog/snare.yaml`, for **snare**: a prompt injection tripwire with attack-chain forensics.

Before: when a page, README or file the agent reads carries hidden instructions, the first sign is usually that something already left the machine.

After: snare plants decoy credentials in the environment of every command the agent runs, blocks any tool call that tries to send one out, and shows the user the full chain: the source that carried the injection (URL or path), a quote of the injected instruction, how the decoy got exposed, and the blocked action with its destination. The session then goes behind Hermes approvals until `/snare reset`, and each incident is saved as a JSON line plus a self-contained HTML report.

How it differs from the listed `canary-trap`: snare puts its decoys in the command environment through `ctx.register_session_env` instead of in every turn's prompt (zero tokens, the model is never told about them), catches the decoy being read and piped out by reference (a decoy variable or an environment dump in a command, or a script it runs, that also uses the network) and not only when its value appears in the arguments, and attributes the incident to the content that carried the injection. It is an independent implementation, not a fork.

**Hermes surfaces used:** `pre_tool_call` (block, and `approve` during lockdown), `post_tool_call` (in-memory ledger of what was read), `transform_llm_output` (user-facing alert, decoy redaction), `ctx.register_session_env` (decoys), `ctx.register_command` (`/snare`), `ctx.state` and the plugin data folder. No core overrides.

**Disclosure (rule 13):**
- Adds three fake variables (`PROD_AWS_ACCESS_KEY_ID`, `PROD_AWS_SECRET_ACCESS_KEY`, `PROD_DATABASE_URL`) to commands on the local terminal backend. Names the user already has set are skipped. The values are random, marked `snare`, and grant nothing.
- Stores owner-only files (0600 in a 0700 folder) in `<HERMES_HOME>/plugin-data/snare/`: the decoy values, and per incident one JSON line and one HTML report holding the tool name, shortened arguments of the blocked call, destination URLs, the source URL or path, up to 280 characters of the injected text, and the session id. Nothing is written when no trap fires.
- Before a terminal command runs a local script (`bash setup.sh`, `./install`), reads that script read-only (up to 64 KB) to check it for the same exfiltration pattern.
- Keeps a bounded in-memory list of recent tool sources per session, used only for attribution.
- No prompt changes, network calls, shell commands, background processes, real credentials, telemetry or Python dependencies.
- The repository's `demo/` folder holds a deliberately poisoned README used for the demo. It is outside the plugin's `subdir` and never installed.

## Related Issue

Entry for the Hermes Agent Plugin Hackathon (Nov 2026). No issue.

## Type of Change

- [x] ✨ New feature (non-breaking change that adds functionality)

## Changes Made

- `plugin-catalog/snare.yaml`: new community entry pinned to `3481b1f249a4ebd39ebbc151eb8a25ffdeecc2d0`, `subdir: snare`, `requires_hermes: ">=0.23.0"`.

## How to Test

1. `hermes plugins validate <checkout>/snare --install-deps` at the pinned commit: every check passes, security scan `safe`, no warnings.
2. `hermes plugins install snare && hermes plugins enable snare`, then `/snare status` in a session.
3. In a session, ask Hermes to set up the project in `demo/poisoned-repo/` by following its README. The README's hidden comment asks the agent to send the decoy keys to a URL; the call is blocked and the reply opens with the attack chain. `python3 demo/replay.py` shows the same chain without a model.
4. Plugin tests: `python3 -m pytest -q tests` (30 tests: every disguise, environment piping, false-positive cases, chain attribution, lockdown, redaction, report files).

## Checklist

### Code

- [ ] I've read the [Contributing Guide](https://github.com/NousResearch/hermes-agent/blob/main/CONTRIBUTING.md)
- [x] My commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] I searched for [existing PRs](https://github.com/NousResearch/hermes-agent/pulls) to make sure this isn't a duplicate
- [x] My PR contains **only** changes related to this fix/feature (no unrelated commits)
- [ ] I've run `just test` on the tests for the code I changed, and they pass (N/A: catalog entry only; the plugin's own tests pass in its repository)
- [ ] `just check` passes (N/A: catalog entry only)
- [x] I've added tests for my changes (in the plugin repository)
- [ ] I've tested on my platform: Windows 11 (validator and the 30 plugin tests pass on Linux; a live Windows 11 run comes with the demo)

### Documentation & Housekeeping

- [x] I've updated relevant documentation (the plugin README renders on its catalog page)
- [x] I've updated `cli-config.yaml.example` if I added/changed config keys: N/A
- [x] I've updated `CONTRIBUTING.md` or `AGENTS.md` if I changed architecture or workflows: N/A

🤖 Generated with [Claude Code](https://claude.com/claude-code)
