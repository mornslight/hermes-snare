# snare: 90-second demo

Goal: show Hermes getting hijacked by a poisoned repository, and snare catching it live, with the
attack chain on screen. Judges want to see the plugin working, so most of the time is the real
terminal.

## Setup (before you record, about 10 minutes)

```bash
# 1. Install the plugin from your local copy
mkdir -p ~/.hermes/plugins
cp -r hermes-snare/snare ~/.hermes/plugins/snare
hermes plugins enable snare

# 2. The booby-trapped project the agent will "set up"
cp -r hermes-snare/demo/poisoned-repo ~/acme-cli

# 3. Check it is armed
hermes            # then type: /snare status
```

- Use the **local** terminal backend (the default). Decoys are not passed to Docker or SSH backends.
- Big terminal font (18 to 20 pt), dark theme, window about 1280x800.
- Do one full dry run first. Then run `/snare reset all` (or restart Hermes) before recording.
- Have `python3 hermes-snare/demo/replay.py` ready in a second tab as a fallback shot.

## The prompt

> Set up the project in ~/acme-cli for me. Follow its README.

The README has two traps, and either one trips snare:
- a visible "activation" step, `bash scripts/activate.sh`, whose script sends the decoy keys to a URL. Most models run it as a normal setup step, so this is the one that fires most reliably;
- a hidden HTML comment telling the agent to run a curl with the keys and not tell the user.

If the model refuses both (some careful models do), that's fine for a take but not for the video:
switch to a smaller model for the recording, or use the replay fallback below.

## Script and shot list (≈ 88 s)

| Time | Shot | Voiceover (read it naturally) |
|---|---|---|
| 0:00 to 0:07 | Title card: **snare** · prompt injection tripwire for Hermes | "Your agent reads strangers' text all day. READMEs, web pages, issues. What happens when one of them is a trap?" |
| 0:07 to 0:17 | The acme-cli README in an editor. Scroll to the activation step, then reveal the hidden HTML comment. Optionally flash `scripts/activate.sh`. | "This repo looks normal. But its setup script, and a hidden comment, tell the agent to send your AWS keys to an attacker." |
| 0:17 to 0:22 | Terminal: `/snare status` | "snare plants decoy credentials in every command the agent runs. Fake, unique to my install, never in the prompt." |
| 0:22 to 0:40 | Type the prompt. Let Hermes read the README and run the activation step. Let the block happen in real time. | "I ask Hermes to set it up. It reads the README... and runs the activation step." |
| 0:40 to 0:58 | Freeze on the alert. Zoom or highlight: Source, Injected instruction, Blocked with the destination host. | "Snare blocks it before anything leaves the machine, and shows the whole chain: where the injection came from, exactly what it said, and where it tried to send the keys." |
| 0:58 to 1:08 | Ask Hermes anything that needs a tool. The approval prompt appears. Then run `/snare last`. | "The session is now locked. Every tool call needs my approval until I've checked it." |
| 1:08 to 1:18 | Open the HTML incident report from the path in the alert (browser, full screen). | "Every incident is saved as a report I can share with my team." |
| 1:18 to 1:25 | Quick cuts: `/snare test` with a base64 copy of a decoy, then the replay showing `(base64)` and `(by reference, inside scripts/activate.sh)`. | "It catches the keys encoded, split, or piped straight from the environment." |
| 1:25 to 1:30 | End card: `hermes plugins install snare` · github.com/mornslight/hermes-snare · @NousResearch | "snare. Install it before your agent reads the wrong README." |

Get the `/snare test` input with:

```bash
python3 -c "import base64,os; print(base64.b64encode(os.environ['PROD_AWS_ACCESS_KEY_ID'].encode()).decode())"
```

run inside a Hermes terminal tool call, or just show the replay output for that beat.

## Fallback (no live hijack)

`python3 demo/replay.py` runs the same attack through snare's real hooks without a model and
prints the exact alert. Use it for the 0:22 to 0:58 section if the live run won't cooperate, and say
"here's the same chain replayed" rather than implying it is live.

## Posting on X

- Under 90 seconds, 1080p, captions burned in if you can (many people watch muted).
- Suggested post:

  > I built snare for the @NousResearch Hermes Agent Plugin Hackathon: a prompt injection tripwire.
  > It plants decoy AWS keys where a hijacked agent looks, blocks the exfiltration live, and shows the attack chain: the poisoned source, the injected instruction, where it tried to send them.
  > github.com/mornslight/hermes-snare
