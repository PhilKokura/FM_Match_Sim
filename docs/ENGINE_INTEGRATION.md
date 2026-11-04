# FM27 native match-engine integration: gates, not promises

## Research basis

Read-only study completed 2026-11-04, documented separately in the user's
match-harness-feasibility.md (research workspace D:\FM27-Research).
The reference project is [PhilipArmstead/FM-24-Match-Harness](https://github.com/PhilipArmstead/FM-24-Match-Harness)
at commit 7f34c8f1f2e1b5715f1cc1c897a034c77ddbfdbc.

The FM24 harness runs in an **already initialized FM24 game process** and
reuses the game's simulation methods. It does not load an independent headless
game service. The upstream GPL-3.0-or-later licence does not grant permission
to distribute or run proprietary FM27 software.

### Candidate FM27 RVA inventory

These are **unexecuted research findings, not verified APIs**. RVAs refer to the
specific game_plugin.dll build with SHA-256
252ff8fb5b7a4a5a5464db6ba632e309eef9b6e65ffa992ae20575a189e66c6a.

| Responsibility | RVA | Evidence scope |
|---|---:|---|
| Fixture-to-match factory | 0xC33370 | Native allocation, constructor, builder call |
| Match serializer thunk | 0x49EF150 | Writes pre-match stream |
| Match reader | 0x4973930 | Deserializes pre-match state |
| Ready/prepare wrapper | 0x16B8DBD0 | Sets up match and ready flag |
| Core play function | 0x4520BD0 | Mode 1, until_tick=-1 used by native caller |
| Match seed | match object +0x20 | Local PCG-derived setup |
| Completion flag | match object +0x15500, bit 2 | Checked by native runner |
| Team references | match object +0x15380/+0x15388 | Struct references, not score offsets |

Unknown: safely initialized runtime host; stream ownership and ABI; all RNG
and global state; reliable final team goals and stats; reset/isolation;
permissions for game-backed automation. Any later FM27 build could invalidate
every RVA. The offline inspector does not establish runtime correctness.

## Strict next milestone: one controlled full match

**Entry criteria:** permission to execute experiments in the game
environment; an initialized and version-verified engine host; validated object
and stream ownership; isolation against crashes and save corruption.

**Pass conditions:**

1. A legitimate fixture is loaded without changing the user's actual save.
2. A newly constructed/deserialized match can be prepared and run to completion.
3. Final team goals are verified against native game outputs; finished is true.
4. Cleanup does not corrupt the process or leave active objects.
5. A fresh instance of the same fixture/seed yields the same validated result
   twice and after an intervening different-seed run.
6. A single tactical change is preserved, with demonstrably unchanged other
   inputs. Only then measure throughput before attempting hundreds of seeds.

**Stop conditions:** no sound runtime hosting contract, unresolved allocator
ownership, unexpected global state mutations, build mismatch, incorrect outputs,
unstable process, or unacceptable licence/integrity risk.

We intentionally do not add an untested native DLL injector or publish
unsupported function-call signatures in this first PR.

## Benchmark protocol

- Each tactic variant uses the same reference fixture, opponent, teams and
  simulation seed set.
- Same seed does not guarantee the same random **events** across different
  tactics. First check whether pairing reduces variance.
- For reproducibility, run **the same inputs and seed twice** and compare
  final outputs. Compare internal RNG fingerprints later if available.
- Prefer pre-registered metrics: goal difference, points and xG difference.
- Compare across multiple fixtures/opponents to avoid overfitting one team.
- The offline comparison's optional 95% CI is a normal approximation shown
  only for n>=30. Use robust uncertainty estimates and held-out fixtures
  before claims of tactical superiority.
