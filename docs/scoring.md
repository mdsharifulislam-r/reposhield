# Scoring and policy

Scores are plain arithmetic, not machine learning, and every finding lists its `scoreFactors`.

## Per-finding score (0–100)

| Factor             | Delta                                                        |
| ------------------ | ------------------------------------------------------------ |
| Severity base      | info 5 · low 15 · medium 35 · high 60 · critical 85          |
| Confidence         | high 0 · medium −4 · low −10                                 |
| Sensitive location | +10 (build/tooling config or dependency manifest)            |
| Install-time       | +10 (npm lifecycle script)                                   |
| Runs at load       | +5 (top-level code in a sensitive file)                      |
| Newly introduced   | +10 (on lines added relative to the base ref)                |
| Correlation        | +10 for 2, +15 for 3+ distinct behaviour classes in one file |

Behaviour classes: `execution`, `network`, `obfuscation`, `credential-access`.

## Severity escalation

Severity is never lowered by scoring. It is raised at most one level, only for medium/high findings, when (a) three or more behaviour classes are correlated in one file, or (b) the finding is newly introduced in a sensitive location. Escalation is recorded in `scoreFactors`.

## Aggregate risk

Highest active finding score + 2 per additional active medium-or-higher finding, capped at 100.

| Score | Level    |
| ----- | -------- |
| 0     | none     |
| 1–24  | low      |
| 25–49 | elevated |
| 50–74 | high     |
| 75+   | critical |

## Policy

`report.safe` is `false` when any **active** finding (not baselined, not allowlisted) is at or above `failOn`, when a `strict` scan is incomplete, or when `strict` hits an unparseable config file. Baselined and allowlisted findings remain in the report. `safe: true` never means proven safe.
