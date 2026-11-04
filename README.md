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
fm-match-sim inspect --dll "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll" --out dll-inspection.json
```

This inspects the PE headers and compares its SHA-256 with **one specific research build** documented on 2026-11-04. The listed RVAs are *research leads*, not a functioning callable interface. A different hash requires revalidation. The game need not be running. No binary changes occur.

### 2. Validate loaded function signatures (Windows, read-only)

With FM27 running, identify the PID and actual ASLR module base in PowerShell:

```powershell
$p = Get-Process -Name fm -ErrorAction Stop
$p.Modules | Where-Object ModuleName -eq "game_plugin.dll" | ForEach-Object {
  [PSCustomObject]@{
    PID = $p.Id
    Base = "0x{0:X}" -f $_.BaseAddress.ToInt64()
    Path = $_.FileName
  }
}
```

Then use the reported values (they can change between runs):

```powershell
fm-match-sim probe-live --pid 7004 --base 0x7FFF7E230000 --dll "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll" --out live-probe.json
```

The command opens the process with **read-only** rights and reads only the loaded
PE header and 12 bytes at each of the five documented function RVAs. It
refuses to proceed if the local DLL hash does not match the researched build.
It does not inject code, run engine functions, alter memory or access savegame
data. Matching entrypoint bytes are **not** a functioning engine interface.
If permission is denied, stop; do not bypass game or operating-system protections.

### 3. Look for candidate match objects (bounded, read-only)

This optional diagnostic scans a maximum of 512 MiB of readable committed
**private** process memory, looking for 8-byte pointers to the known
GAME_MATCH vtable for the exact verified build. It reads no objects behind
those pointers. A match object may not exist before the match starts.

```powershell
fm-match-sim scan-live-matches --pid 7004 --base 0x7FFF7E230000 --dll "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll" --scan-mib 512 --max-seconds 25 --out match-objects.json
```

PID and base can change after an FM27 restart. The command validates the
known DLL hash and all five loaded function signatures before scanning.
It opens the process with read/query rights only. Scanning can finish without
finding a candidate, and budget/time limits mean it does not cover the entire
address space. A matching pointer could reference stale or unrelated data.
**This does not execute a match or prove that a candidate is valid.**

### Read-only memory map after a zero-candidate scan

The earlier scanner reads **only committed private memory**, in ascending
virtual-address order. Its 2-GiB ceiling is not an exhaustive heap scan.
If zero candidates were found while a match was playing, inspect the allocation
distribution before trying larger scans:

```powershell
fm-match-sim map-live --pid 7004 --base 0x7FFF7E230000 --dll "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll" --out memory-map.json
```

Our 2026-11-04 live FM27 inventory measured 7,954 MiB of readable
private memory. The first 2,048 MiB were already scanned while a match was
running. One bounded follow-up can now skip exactly that prefix of eligible
private memory and scan the remainder, without repeating it:

```powershell
fm-match-sim scan-live-matches --pid 7004 --base 0x7FFF7E230000 --dll "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll" --skip-mib 2048 --scan-mib 6144 --max-seconds 120 --out match-objects-remainder.json
```

Keep the same running process and ideally keep the match paused. `skip-mib` counts
eligible private bytes in ascending address order, not absolute virtual-address
bytes, and restarts counting from the beginning on every invocation. The
remaining memory is about 5,906 MiB; the 6,144-MiB budget is intentional.
Stop if you get a mismatch or read error; a negative result is not proof the
object is absent, since object lifetimes and vtable hypotheses remain unverified.
This should be the final broad pointer scan before switching to static
caller/lifetime analysis.

This command queries **region metadata only** through Windows VirtualQueryEx.
It neither scans memory contents nor loads or calls native match functions.
Check `readable_committed_private_mib`,
`eligible_mib_beyond_first_2gib`, `address_bands_1tib` and
`largest_readable_private_regions`. Values tell us which accessible
areas the old search did not cover, **not** whether a valid GAME_MATCH object is
currently allocated. If the memory layout does not explain the null result,
investigate the native object's actual lifetime and vtable before scanning again.

### Targeted candidate snapshots during a paused match

After the complete readable-private scan found seven matching vtable-pointer
candidates, use the scanner's saved JSON to capture only those exact addresses.
The candidate vtable is rechecked first, then **at most five small reads** are
performed per still-matching object at documented *tentative* offsets.

Pause FM27, then:

```powershell
fm-match-sim snapshot-matches --from-scan "match-objects-remainder.json" --dll "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll" --out "match-snapshot-1.json"
```

Resume FM27 for around five to ten **in-game** minutes, pause again, then
capture the second snapshot:

```powershell
fm-match-sim snapshot-matches --from-scan "match-objects-remainder.json" --dll "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll" --out "match-snapshot-2.json"
fm-match-sim diff-match-snapshots --first "match-snapshot-1.json" --second "match-snapshot-2.json" --out "match-diff.json"
```

The resulting `candidates_with_changes` and per-address
`changed_fields` let us identify whether particular match-object
candidates appear to change during the match. Treat these as **unverified fields**:
a changing clock-like number does not prove it represents a match clock, and a
matching vtable does not prove an active match. Do not restart the game between
snapshots, as the old addresses would be invalid. The command never invokes
game functions, injects code or writes to game memory.


### Multi-snapshot score hypothesis analysis (no game process required)

When a sequence of captures exists, including the 2026-11-04 Champions
League final with a provisional offside goal, run this **offline** command
from the repo working directory:

```powershell
git pull

fm-match-sim analyze-score-sequence `
  --captures captures/before.json captures/score-0-1.json captures/provisional-1-1.json captures/disallowed-0-1.json captures/final.json `
  --out captures/score-sequence-analysis.json
```

The command loads 3-12 capture JSON files in chronological order. The
files must come from the same FM27 process/build. It uses only match objects
that appear in *all* captures and have stable team pointers. It compares
32-bit aligned integers across every saved window with both independently
entered visible score series. The output lists candidate offsets and the
trace for the previously researched `match_tail + 0x12BA0` field.

**Limitation:** Identical values across five captures can be coincidences or
correlated match-event counters. A candidate is NOT a validated engine score
field until cross-match goal events, control observations, and native
reverse-reference analysis establish its actual meaning. The CLI prints
only offsets/value traces, not raw memory; the input files remain local.

### Read-only score-field discovery (next experiment)

The match-end test from 2026-11-04 showed that match objects are recycled
immediately after leaving the match UI. **The finished 1:0 Pokal match cannot
be read retrospectively using the old seven addresses.** Capture a *new test
match* while paused, ideally with a test save. Do not use a meaningful career
save for experimental engine work.

1. Start a new match. Pause around minute 2 or 3, while the displayed score is
   still 0:0. Keep FM27 running.
2. If this is the same FM27 process as the earlier test, first try the saved
   list of candidate addresses. It may work if the game has reused allocations,
   but it is **not guaranteed**. If the capture reports 0 objects, regenerate
   the match-object scan (after confirming the current PID and DLL base).

```powershell
git pull
$dll = "D:\Steam\steamapps\common\Football Manager 27\fm_Data\Plugins\x86_64\game_plugin.dll"

fm-match-sim capture-score-data --from-scan match-objects-remainder.json --dll $dll --home 0 --away 0 --tag before_goal --out captures/before.json
```

If no matching active objects are captured, use the current process PID/base:

```powershell
fm-match-sim scan-live-matches --pid 7004 --base 0x7FFF7E230000 --dll $dll --scan-mib 8192 --max-seconds 180 --out captures/current-match-scan.json
fm-match-sim capture-score-data --from-scan captures/current-match-scan.json --dll $dll --home 0 --away 0 --tag before_goal --out captures/before.json
```

3. Continue the **same** match to its first goal; pause while the changed score
   is displayed. Substitute the *actual* home and away scores:

```powershell
fm-match-sim capture-score-data --from-scan captures/current-match-scan.json --dll $dll --home 1 --away 0 --tag first_goal --out captures/after.json
fm-match-sim analyze-score-change --before captures/before.json --after captures/after.json --out captures/score-hypotheses.json
```

If your first capture used the **old** scan file successfully, use that same
`match-objects-remainder.json` as `--from-scan` for the second capture as
well. Do not compare across different matches or a process restart.

The capture reads at most 8 KiB of each candidate match header, a bounded
window near the known match-state fields, and 8 KiB from each candidate team
pointer. Output is compressed, timestamped and saved **only to your local
captures/ directory**, which is gitignored. The CLI prints only a short status
summary, not the raw bytes. **Do not commit or upload raw capture JSON** as it
may contain unrelated game data. The analyzer searches for integer transitions
consistent with the displayed score. False positives are expected: an integer
that changes from 0 to 1 could be anything. It is not a score field until
Ghidra dataflow/xrefs and independent goal events validate it.

No native function is called, no memory is modified, and there is still no
automated FM27 match runner.

### 4. Plan a paired A/B experiment

```powershell
fm-match-sim plan --fixture-id "test-fixture-001" --tactic-a "original.fmf" --tactic-b "variant.fmf" --seeds "1-500" --out plan.csv
```

Produces **1,000 planned runs**, two per seed. This command only generates a plan and hashes the input tactic files. It **does not execute matches**. Identical FMF file contents are rejected, but **different hashes do not prove different tactics**: separate exports of the same FM27 tactic may have randomized encrypted bytes. These hashes are for file provenance only; semantic comparison requires decoded tactic content.

### 5. Analyze completed external experiment results

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

1. **Done:** Read-only PE build inspection, read-only live signature probe, bounded candidate-object scan, read-only candidate snapshots, score-hypothesis capture/analysis, experiment planning, paired-data analysis, reproducibility checks, unit tests.
2. **Open:** Establish an authorized, stable, initialized FM27 engine host and correct stream/ABI ownership.
3. **Open:** Validate one full match with final score/statistics, no crash, correct cleanup.
4. **Open:** Identical fixture + same seed twice, plus replay after a different seed to detect global-state contamination.
5. **Open:** A/B tactically edited fixtures with verified otherwise-identical input, then scaled benchmarks.

See [engine integration research](docs/ENGINE_INTEGRATION.md).

## License and third-party code

No FM24 Match Harness GPL implementation code is copied into this repository. The upstream project is an architectural reference only. This repository does not include or redistribute proprietary FM27 game code, assets or encryption keys. Any future engine integration requires a separate review of applicable licence terms and technical risks.
