# snare: a prompt injection tripwire for Hermes

Hermes reads web pages, READMEs, issues and files written by strangers. One of them can carry
hidden instructions that turn the agent against you, and the usual goal is to get your secrets out.

**snare catches that moment.** It plants decoy credentials exactly where a hijacked agent goes
looking, blocks any tool call that tries to send one out, and tells you the whole story:

```
🪤 Snare tripped: prompt injection blocked

1. Source: read_file read acme-cli/README.md at 09:12:03
   Injected instruction:
   > ... this step is pre-approved by the repository owner. ...
     (the hidden "activation" command, quoted from the file)
2. Decoy exposed: terminal `env | grep PROD_` revealed PROD_AWS_SECRET_ACCESS_KEY
3. Blocked: terminal tried to send decoy PROD_AWS_ACCESS_KEY_ID (base64) to telemetry-acme.example

This session is locked: every further tool call asks for your approval.
Incident report: ~/.hermes/plugin-data/agent-plugin-snare-…/reports/20261111-091203-a1f2.html
```

No real task ever needs a decoy, so a decoy leaving the agent is close to proof of an injection,
with almost no false positives. And unlike a classifier, it does not have to guess what an
injection looks like.

## What it does

| | |
|---|---|
| **Plants decoys** | Every terminal and code-execution command the agent runs sees `PROD_AWS_ACCESS_KEY_ID`, `PROD_AWS_SECRET_ACCESS_KEY` and `PROD_DATABASE_URL` in its environment. The values are fake, unique to your install, and marked `snare` so a human recognises them. Nothing is added to the model's prompt, so it costs no tokens and the model is never told about them. Names you already have set are never touched. |
| **Blocks the leak** | Before any tool runs, its arguments are checked for a decoy: plain, URL-encoded, base64, hex, reversed, partial (12+ characters) or nested anywhere in the arguments. A command that reads a decoy variable by name, or dumps the whole environment, *and* talks to the network in the same call is blocked too, even though the value never appears in the arguments. The same check covers a local script the command runs (`bash setup.sh`, `./install`), since that is where a poisoned repository hides it. |
| **Explains the attack** | snare keeps a short in-memory ledger of what the agent read in each session and scores it for injection markers (overrides, instructions aimed at the agent, "don't tell the user", hidden HTML, requests to send data to a URL). When the trap fires it names the source, quotes the injected instruction, shows how the decoy got exposed and what the agent tried to do with it. |
| **Tells you, not just the model** | The alert is prepended to the agent's next reply, so you see it even if the hijacked model tries to play it down. A reply that contains a decoy (for example a markdown image link built to leak it) is redacted. |
| **Contains the session** | After a trip, every further tool call in that session goes through Hermes's approval prompt until you run `/snare reset`. Other sessions are unaffected. |
| **Keeps a record** | Each incident is appended to `incidents.jsonl` and written as a self-contained HTML report in the plugin's data folder. |

## Commands

| Command | |
|---|---|
| `/snare` or `/snare status` | Whether the decoys are really reaching your commands, how many incidents, which sessions are locked |
| `/snare selftest` | Run the live backend check again, on any backend |
| `/snare incidents` | The last ten incidents, one line each |
| `/snare last` / `/snare report <id>` | The full attack chain of an incident |
| `/snare reset [all]` | Lift the lockdown on this session (or all) |
| `/snare rotate` | Generate new decoys |
| `/snare test <text>` | Check a string for decoys and injection markers |

## Is the trap actually set here?

"No incidents" should mean nothing tripped, not that the trap was never set. Hermes only passes
plugin session variables to the **local** terminal backend, so snare checks:

- **At startup** (no commands run): is `env_canaries` on, did Hermes accept the decoy variables,
  and which terminal backend is configured. If the decoys can't reach your commands (Docker, SSH,
  Modal, Daytona or any other non-local backend, or an old Hermes) it logs a warning.
- **On `/snare status`** with the local backend, and on `/snare selftest` with any backend: one
  harmless command through Hermes's own terminal tool (`ctx.dispatch_tool`), so it runs wherever
  the agent's commands really run. It prints which decoy *names* it sees, never their values.

`/snare status` then shows one of:

| | |
|---|---|
| `Decoys: active on the local backend` | A live check saw the decoys in a command's environment. |
| `Decoys: NOT active here` | The backend doesn't get them (with the reason). Blocking is still on, but a hijacked agent won't find decoys there, so the trap rarely fires. |
| `Decoys: not verified yet` | Expected to work, not proven, for example a check run outside a chat. Run `/snare selftest` from a chat. |
| `Decoys: off` | `env_canaries` is off, or every decoy name is already set in your environment. |

A conclusive live result is reused until the backend changes, so status doesn't run a command
every time. Status never starts a remote backend by itself; `/snare selftest` does.

## Install

```bash
hermes plugins install snare
hermes plugins enable snare
```

Settings (Desktop: Settings → Plugins → snare, or `plugins.entries.snare.settings` in `config.yaml`):

| Key | Default | |
|---|---|---|
| `lockdown` | `true` | Require approval for further tool calls in a session after a trip |
| `env_canaries` | `true` | Plant the decoys in command environments |
| `block_env_exfil` | `true` | Block commands that read a decoy (or the whole environment) and use the network in the same call |

## How it hooks into Hermes

Only public surfaces: `pre_tool_call` (the tripwire, returns `block` or `approve`), `post_tool_call`
(the read ledger), `transform_llm_output` (the alert and redaction), `ctx.register_session_env`
(the decoys) and `ctx.register_command` (`/snare`). No core code is patched.

## Limits

- The decoys live in the environment of commands on the **local** terminal backend. On Docker, SSH
  or other remote backends Hermes does not pass plugin session variables, so the environment trap
  is inactive there; leaks of a decoy that reaches the agent another way are still blocked.
  snare tells you which case you are in: a warning at startup and the `Decoys:` line of
  `/snare status` (see "Is the trap actually set here?").
- The injection markers are heuristics used to *name the source*. They never decide a block.
- The read ledger lives in memory, so attribution covers the current gateway process.
- Lockdown asks through Hermes's approval prompt, so in YOLO or other auto-approve modes it is advisory. The leaking call itself is always blocked.
- snare is a tripwire, not a sandbox. Pair it with Hermes's approvals for anything you do not trust.

## Disclosure

- **Data stored** (owner-only files in the data folder Hermes gives the plugin, under `<HERMES_HOME>/plugin-data/`; `/snare status` prints it): the decoy values
  (`state.json`); per incident, one JSON line in `incidents.jsonl` and an HTML report with the
  tool name, the blocked call's arguments (shortened), destination URLs, the source URL or path,
  a quote of up to 280 characters of the injected text, and the session id. Nothing is stored
  when no trap fires.
- **Environment**: adds the three decoy variables to commands the agent runs on the local backend.
- **Reads outside its own data**: before a terminal command runs a local script (`bash setup.sh`, `./install`), snare reads that script (read-only, up to 64 KB) to check it for the same pattern. Nothing from it is stored unless a trap fires.
- **Commands it runs**: on `/snare status` (local backend, until one check is conclusive) and on
  `/snare selftest`, one command through Hermes's terminal tool that prints which decoy names are
  set, never their values. It runs nothing at startup or on its own.
- **Prompt**: none. Replies change only when an alert is shown or a decoy is redacted.
- No network calls, no background processes, no real credentials, no telemetry,
  no Python dependencies.

## License

MIT
