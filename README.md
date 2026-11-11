# hermes-snare

**snare** is a prompt injection tripwire plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent).
It plants decoy credentials where a hijacked agent goes looking, blocks any attempt to send one out,
and shows the attack chain: the page or file that carried the injection, what it said, how the decoy
was exposed and what the agent tried to do.

The plugin lives in [`snare/`](snare/); its README is the full documentation.

```
snare/            the Hermes plugin (this is what the catalog installs)
tests/            unit tests, plus an integration check against a Hermes checkout
e2e/              end-to-end run: the real Hermes agent loop, with a scripted model playing the hijacked agent
demo/             a booby-trapped README for the demo, and a model-free replay script
```

`demo/poisoned-repo/README.md` contains a deliberate prompt injection (that is the point of it).
It sits outside the plugin directory and is never installed.

## Develop

```bash
python3 -m pytest -q tests                  # unit tests
python3 demo/replay.py                      # see the alert without a model
hermes plugins validate ./snare             # Hermes's own admission checks
HERMES=../hermes-agent bash e2e/run_e2e.sh  # end to end through a Hermes checkout
```

`e2e/run_e2e.sh` runs Hermes with snare enabled against the poisoned demo repo. The model is a
local scripted stand-in (no API key) that reads the README and runs its activation step, so every
other part is real: plugin loading, the agent loop, the terminal tool, the hooks and the report.
`SNARE=off` runs the same attack without snare as a control, and `SCENARIO=comment` obeys the
hidden HTML comment instead.

MIT licensed.
