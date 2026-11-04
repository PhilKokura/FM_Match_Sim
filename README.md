# FM Match Sim

**FM27 experimental match-simulation research workspace.**

> **Status: offline research foundation only.** This repository **does not yet run FM27 matches**, inject code into the game, control a live engine, or make claims about reproducibility or throughput.

The first milestone provides a version-aware, read-only binary inspection tool and the statistical infrastructure needed once an independently validated match-engine adapter exists.

## Quick start

Python 3.11+, standard library only at runtime:

```powershell
python -m pip install -e .
python -m fm_match_sim --help
python -m unittest discover -s tests -v
```

### 1. Check the installed FM27 binary

```powershell
fm-match-sim inspect --dll "D:\\Steam\\steamapps\\common\\Football Manager 27\\fm_Data\\Plugins\\x86_64\\game_plugin.dll" --out dll-inspection.json
```

This inspects the PE headers and compares its SHA-256 with **one specific research build** documented on 2026-11-04. The listed RVAs are *research leads*, not a functioning callable interface. A different hash requires revalidation. The game need not be running. No binary changes occur.

### 2. Plan a paired A/B experiment

```powershell
fm-match-sim plan --fixture-id "test-fixture-001" --tactic-a "original.fmf" --tactic-b "variant.fmf" --seeds "1-500" --out plan.csv
```

Produces **1,000 planned runs**, two per seed. This command only generates a plan and hashes the input tactic files. It **does not execute matches**. Identical FMF contents are rejected.

### 3. Analyze completed external experiment results

Once a separate real FM27 adapter can produce CSVs with columns `seed,home_goals,away_goals`, plus optional `home_xg,away_xg,finished`:

```powershell
fm-match-sim compare --original results-original.csv --variant results-variant.csv --out comparison.json
fm-match-sim verify-repeat --first repeat-1.csv --second repeat-2.csv
```

- A/B comparisons match **the same seed** across tactics. Every seed must represent the same controlled fixture, teams and home perspective.
- Differences are **B minus A**. Goal-difference and points are from the home team's perspective.
- The optional 95% interval is a normal approximation for at least 30 paired results; it is exploratory, not a substitute for study design or holdout fixtures.
- Result-level equality for repeated inputs is useful but not evidence that the native RNG state or event path was identical.

## Roadmap and evidence gates

1. **Done:** Read-only PE build inspection, experiment planning, paired-data analysis, reproducibility checks, unit tests.
2. **Open:** Establish an authorized, stable, initialized FM27 engine host and correct stream/ABI ownership.
3. **Open:** Validate one full match with final score/statistics, no crash, correct cleanup.
4. **Open:** Identical fixture + same seed twice, plus replay after a different seed to detect global-state contamination.
5. **Open:** A/B tactically edited fixtures with verified otherwise-identical input, then scaled benchmarks.

See [engine integration research](docs/ENGINE_INTEGRATION.md).

## License and third-party code

No FM24 Match Harness GPL implementation code is copied into this repository. The upstream project is an architectural reference only. This repository does not include or redistribute proprietary FM27 game code, assets or encryption keys. Any future engine integration requires a separate review of applicable licence terms and technical risks.
