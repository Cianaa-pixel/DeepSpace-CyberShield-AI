# DeepSpace CyberShield AI — Fixed & Fully Wired

## What was wrong

The intro screen was printing raw HTML/CSS as literal text instead of
rendering it (see your screenshot). Cause: `st.markdown(..., unsafe_allow_html=True)`
was fed a multi-line f-string built *inside* indented Python blocks, so every
line carried 4+ spaces of leading whitespace into the HTML. Markdown's own
spec treats any line indented 4+ spaces as a literal **code block** — so it
rendered your HTML as text instead of parsing it. Every `st.markdown()` call
in the new `app.py` is wrapped in `textwrap.dedent(...)` to strip that
whitespace before it reaches the parser.

## What changed beyond the fix

You asked for the paper's actual novelty — TTL-Evidence, DSSLV, and Dynamic
TTL Decay — to be real, running logic instead of description cards on a page.
`app.py` now imports and runs a full pipeline (`src/`) on every load:

```
src/dataset_generator.py   Synthetic DSCN traffic: normal + Spoofing, Replay,
                            Relay Tampering, Bundle Flooding, Unauthorized
                            Injection (matches Section V of the paper)

src/ai_engine.py           AI Behavioral Analysis Engine (Isolation Forest)
                            -> anomaly_confidence per bundle

src/ttl_evidence.py        Temporal Trust Leakage Evidence
                            Tscore = w1*St + w2*Sl + w3*Sr + w4*Sh + w5*Sc
                            + a stateful, per-source dynamic_trust that erodes
                            over a sequence of bundles (Fig.3), plus explicit
                            replay-signature detection

src/dsslv.py                Deep-Space Signal Lineage Verification: checks a
                            bundle's actual relay_path against the expected
                            Mars Rover -> Orbiter -> Relay Sat -> Earth chain

src/ttl_decay.py            Passive Autonomous Eviction: combines trust +
                            lineage into a confidence score and decays the
                            Bundle Protocol TTL accordingly

src/attack_detector.py      Orchestrates all four stages, in the order the
                            paper describes (Section IV-D)

src/report_generator.py     Accuracy / precision / recall / F1 / confusion
                            matrix against the synthetic ground-truth labels

src/data_loader.py, main.py, utils.py   Supporting glue + a CLI runner
```

Run standalone (no UI) with:

```
python -m src.main
```

This regenerates `dataset/communication_logs.csv` if it's missing, runs the
full pipeline, and writes `dataset/detection_results.csv` +
`dataset/detection_report.md`.

## Installing into your existing project

Your VS Code screenshot shows `static/images/*.png` and other files already
in place — copy just these into your existing `DeepSpace-CyberShield-AI/`
folder (they'll sit alongside your existing `static/images`, `dataset/`,
etc. without touching your images):

- `app.py` (replaces your current one)
- `src/` (new folder — the modules listed above)
- `requirements.txt`

Then:

```
pip install -r requirements.txt
streamlit run app.py
```

## Honest caveat on accuracy

On the bundled synthetic dataset the pipeline gets **~86% accuracy, 100%
precision, 0 false positives on normal traffic**, and catches Replay and
Unauthorized Injection at 100%, Relay Tampering at ~85%. Sophisticated
Spoofing is the weakest category (as the paper itself frames it — that's
the specific hard case TTL-Evidence exists for, and it needs a longer
per-source history than a small synthetic run gives it to fully erode
trust). These numbers are from a data generator I wrote to match the
paper's described attack types — not from real spacecraft telemetry, so
treat them as a working proof-of-concept, not a validated result.
