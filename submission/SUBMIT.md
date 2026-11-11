# Submitting snare (due Nov 11, 5:00 PM Eastern)

Everything below is ready except the steps that need your GitHub and X accounts.

## 1. Put the plugin in a public repo (done)

Pushed to https://github.com/mornslight/hermes-snare at commit `3481b1f249a4ebd39ebbc151eb8a25ffdeecc2d0`.
Still yours: paste the repo description on GitHub (gear icon next to About).

For reference, the commands were:

Create an **empty public** repo on GitHub named `hermes-snare` (no README, no license; they're
already in the folder). Then either tell me to push it, or push it yourself:

```bash
cd hermes-tripwire          # this folder
git init -b main
git add .
git commit -m "feat: snare, a prompt injection tripwire for Hermes Agent"
git remote add origin https://github.com/mornslight/hermes-snare.git
git push -u origin main
git rev-parse HEAD          # pinned: 3481b1f249a4ebd39ebbc151eb8a25ffdeecc2d0
```

Before the commit, swap your name or handle in for "Jackson" in `snare/plugin.yaml` (`author:`) and
both `LICENSE` files if you want something else shown.

## 2. Check it the way catalog CI will (2 minutes, needs Hermes installed)

```bash
hermes plugins validate ./snare --install-deps
```

Already run here with Hermes's own validator code at today's `main`: every check passes, security
scan `safe`, no warnings.

## 3. Open the catalog PR (about 5 minutes)

1. Fork `NousResearch/hermes-agent` on GitHub.
2. Add `plugin-catalog/snare.yaml` from `submission/plugin-catalog/snare.yaml` (the commit is already pinned).
3. Commit with `feat(plugin-catalog): add snare`.
4. Open the PR against `main` with the title and body from `submission/PR.md` (replace
   `TESTED_PLATFORM`, and tick the two boxes you've done yourself).

## 4. Record and post the demo

Follow `submission/DEMO.md`. Keep it under 90 seconds and tag @NousResearch.

## 5. Submit the form

Paste the PR link and the X post link into the hackathon Typeform from the announcement.
