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
} from "reposhield-scan";
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

`clean()` accepts the usual scan options plus `remove?: boolean` and `removeSource?: boolean`. It is read-only by default. With `remove: true`, it removes matched active critical VS Code task and npm-script entries, then previews critical JS/TS paths in report notes. `removeSource: true` explicitly deletes those entire source files. `scan()` remains read-only.

The CLI also provides `reposhield run [scan options] -- <command> [args...]`. It scans first and starts the requested command only when the report passes policy. `scan --remove` and `run --remove` remove matched task/script entries and preview source candidates. `--remove-source --yes` confirms whole-file source deletion. This is a heuristic gate, not proof of safety, and cannot stop commands launched outside the wrapper; enforce scans in CI too. The scanner itself never executes scanned source.

`reposhield init` previews npm script changes; `reposhield init --yes` preserves every user-defined script, including lifecycle hooks, under `reposhield:init:original:*` and adds version-pinned scan wrappers. Init itself does not run package managers or scripts. If it finds `server.ts`, it can generate a separate bootstrap that calls `clean()` before dynamically importing the server; it does not inject a scan after static imports.

## Functions

- `clean(options?) → Promise<Report>`: scans and reports; `{ remove: true }` enables structured cleanup, while `{ remove: true, removeSource: true }` explicitly deletes whole critical source files.
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
