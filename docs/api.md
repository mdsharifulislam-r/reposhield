# API reference

All functions are read-only unless stated. None executes scanned code.

```ts
import {
  clean,
  scan,
  scanFile,
  compareWithBaseline,
  createBaseline,
  generateReport,
  inspectRecovery,
  renderRecoveryPlan,
  monitor,
} from "reposhield";
```

## Options (`RepoShieldOptions`)

| Option                 | Type                                  | Default   | Notes                                                                   |
| ---------------------- | ------------------------------------- | --------- | ----------------------------------------------------------------------- |
| `root`                 | `string`                              | `"."`     | Scan root. Nothing outside it is read.                                  |
| `mode`                 | `audit｜strict｜ci｜changed｜monitor` | `audit`   | `strict` lowers the default `failOn` to `medium`.                       |
| `includeGitHistory`    | `boolean`                             | `true`    | Read-only Git analysis. Degrades gracefully without Git.                |
| `baseline`             | `boolean｜string`                     | `false`   | `true` = `.reposhield-baseline.json`; a string is a path inside `root`. |
| `failOn`               | severity                              | `high`    | Policy threshold.                                                       |
| `minConfidence`        | `low｜medium｜high`                   | `low`     | Drop findings below this confidence.                                    |
| `ignore`               | `string[]`                            | `[]`      | Extra globs, added to the built-in ignore list.                         |
| `replaceDefaultIgnore` | `boolean`                             | `false`   | Discouraged: replaces the built-in list.                                |
| `respectGitignore`     | `boolean`                             | `true`    |                                                                         |
| `maxFileSizeBytes`     | `number`                              | `1000000` | Larger files are skipped and reported (`RS-SCAN-002`).                  |
| `maxFiles`             | `number`                              | `50000`   | Scan is marked incomplete (and fails `strict`) when hit.                |
| `concurrency`          | `1–64`                                | `8`       |                                                                         |
| `followSymlinks`       | `boolean`                             | `false`   | Only symlinks that stay inside `root`.                                  |
| `baseRef`              | `string`                              | auto      | Git ref for `changed` mode and "newly introduced" marking.              |
| `disabledRules`        | `string[]`                            | `[]`      |                                                                         |
| `severityOverrides`    | `Record<ruleId, severity>`            | `{}`      |                                                                         |
| `allowlist`            | `{ruleId, path?, reason}[]`           | `[]`      | `reason` required. Allowlisted findings stay visible.                   |
| `redactSecrets`        | `boolean`                             | `true`    |                                                                         |
| `monitorIntervalMs`    | `number ≥ 1000`                       | `30000`   |                                                                         |
| `signal`               | `AbortSignal`                         | —         | Cancels a running scan.                                                 |

Invalid options throw `ConfigError` listing every problem.

## Functions

- `clean(options?) → Promise<Report>`: alias of `scan`. Scans and reports only.
- `scan(options?) → Promise<Report>`
- `scanFile(filePath, options?) → Promise<Report>`: refuses paths outside `root` and escaping symlinks.
- `compareWithBaseline(options?) → { baselineFound, newFindings, accepted, resolved, report }`
- `createBaseline({ ...options, includeCritical? }) → { path, baseline, excluded, report }`: **writes the baseline file only.**
- `generateReport(report, { format: "text"｜"json"｜"sarif", color? }) → string`
- `inspectRecovery(options?) → RecoveryInspection`: read-only; `renderRecoveryPlan(inspection) → string`.
- `monitor(options, handlers) → MonitorHandle`: starts only when called; `handle.stop()` shuts down cleanly. Also stops on `signal`.

## `Report`

`tool`, `mode`, `root`, `generatedAt` (omitted in `ci` mode), `safe`, `policy { failOn, failedBecause[] }`, `summary`, `findings[]`, `errors[]`, `notes[]`, `git`, `disclaimer`.

Each `Finding` has `ruleId`, `title`, `category`, `severity`, `confidence`, `file`, `location`, `message`, `evidence[]`, `recommendation`, `score`, `scoreFactors[]`, `correlatedWith?`, `newlyIntroduced?`, `fingerprint`, `baselined?`, `allowlisted?`.

Findings are sorted deterministically (severity, score, file, line, rule).
