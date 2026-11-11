"""Original synthesized background track for the snare demo (88 s, 48 kHz stereo WAV).

Everything is generated here from sine waves and noise: no samples, no downloaded music.
Timeline follows the video's scenes:
  0-17   low drone fades in (title, poisoned README)
  17-33  a pulse enters and builds while Hermes runs the hijacked task
  33     impact: snare blocks the call
  33-82  calmer pad under the alert, comparison and records, pulse back at low level
  82-88  resolves to a major chord on the end card and fades out
Usage: python3 make_audio.py OUT.wav
"""
import sys
import wave

import numpy as np

SR, DUR = 48000, 88.0
N = int(SR * DUR)
t = np.arange(N) / SR
rng = np.random.default_rng(7)


def env(points):
    """Piecewise-linear envelope from (time, level) points."""
    xs, ys = zip(*points)
    return np.interp(t, xs, ys)


def tone(freq, detune=0.0):
    return np.sin(2 * np.pi * freq * t) + 0.5 * np.sin(2 * np.pi * (freq * (1 + detune)) * t)


def lowpass(x, cutoff):
    """One-pole low-pass, cutoff in Hz."""
    a = np.exp(-2 * np.pi * cutoff / SR)
    y = np.empty_like(x)
    acc = 0.0
    for i in range(len(x)):  # small enough to loop over once
        acc = (1 - a) * x[i] + a * acc
        y[i] = acc
    return y


# --- drone: A minor colour (A1, E2, C3), slow breathing -----------------------------------
breath = 0.88 + 0.12 * np.sin(2 * np.pi * 0.08 * t)
drone_minor = (0.55 * tone(55.0, 0.003) + 0.35 * tone(82.41, 0.002) + 0.18 * tone(130.81, 0.004)) * breath
drone_major = (0.55 * tone(55.0, 0.003) + 0.35 * tone(82.41, 0.002) + 0.20 * tone(138.59, 0.004)
               + 0.12 * tone(220.0, 0.002)) * breath
minor_lvl = env([(0, 0), (4, 0.28), (17, 0.32), (33, 0.75), (34, 0.3), (80, 0.3), (83, 0.0), (88, 0)])
major_lvl = env([(0, 0), (80, 0), (83, 0.42), (86, 0.38), (88, 0)])
drone = drone_minor * minor_lvl + drone_major * major_lvl

# --- pulse: soft low thump at 100 bpm, builds into the hijack ----------------------------
bpm = 100.0
beat = 60.0 / bpm
pulse = np.zeros(N)
k_len = int(0.35 * SR)
kt = np.arange(k_len) / SR
kick = np.sin(2 * np.pi * (45 + 60 * np.exp(-kt * 30)) * kt) * np.exp(-kt * 9)
start = 17.0
n_beats = int((82.0 - start) / beat)
for b in range(n_beats):
    s = int((start + b * beat) * SR)
    pulse[s:s + k_len] += kick[: max(0, min(k_len, N - s))]
pulse_lvl = env([(0, 0), (17, 0.12), (25, 0.4), (33, 0.75), (33.2, 0.0), (36, 0.0), (40, 0.18),
                 (80, 0.18), (82, 0.0), (88, 0)])
pulse *= pulse_lvl

# --- riser: filtered noise swell into the block --------------------------------------------
noise = rng.standard_normal(N)
riser = lowpass(noise, 900) * env([(0, 0), (27, 0), (33, 0.35), (33.05, 0), (88, 0)])

# --- impact at 33 s: low boom plus a short bright hit ----------------------------------------
hit = np.zeros(N)
h0 = int(33.0 * SR)
hl = int(2.5 * SR)
ht = np.arange(hl) / SR
boom = np.sin(2 * np.pi * (38 + 80 * np.exp(-ht * 12)) * ht) * np.exp(-ht * 2.2)
crack = lowpass(rng.standard_normal(hl), 3000) * np.exp(-ht * 18) * 0.6
hit[h0:h0 + hl] = (boom + crack)[: N - h0]

# --- soft high shimmer on the end card ----------------------------------------------------
shimmer = (np.sin(2 * np.pi * 659.25 * t) + np.sin(2 * np.pi * 880.0 * t) * 0.6) * \
    env([(0, 0), (82, 0), (84, 0.05), (87, 0.03), (88, 0)])

mix = 0.9 * drone + 0.8 * pulse + riser + 0.9 * hit + shimmer
# small stereo width: slight delay on the right channel for the pad, centred hits
right = np.roll(0.9 * drone, int(0.012 * SR)) + 0.8 * pulse + riser + 0.9 * hit + shimmer
stereo = np.stack([mix, right], axis=1)
stereo *= env([(0, 0), (3, 1), (85, 1), (88, 0)])[:, None]  # global fade in/out
stereo /= np.max(np.abs(stereo)) * 1.05

with wave.open(sys.argv[1], "wb") as w:
    w.setnchannels(2)
    w.setsampwidth(2)
    w.setframerate(SR)
    w.writeframes((stereo * 32767).astype("<i2").tobytes())
print("wrote", sys.argv[1], DUR, "s")
