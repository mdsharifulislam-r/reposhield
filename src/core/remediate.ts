import fs from "node:fs/promises";
import path from "node:path";
import { applyEdits, modify } from "jsonc-parser";
import { inspectVSCodeTasks } from "../rules/vscode.js";
import type { Report } from "./types.js";
import { isInside } from "./options.js";

export interface RemediationResult {
  taskEntriesRemoved: number;
  packageScriptsRemoved: number;
  sourceFilesPreview: string[];
  sourceFilesRemoved: number;
}

const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);

function formattingOptions(text: string) {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  return { insertSpaces: true, tabSize: 2, eol };
}

function relativeFileIsSafe(rootAbs: string, relativeFile: string): string | undefined {
  const fileAbs = path.resolve(rootAbs, relativeFile);
  return isInside(rootAbs, fileAbs) ? fileAbs : undefined;
}

async function regularFileInsideRoot(rootAbs: string, rootReal: string, relativeFile: string) {
  const fileAbs = relativeFileIsSafe(rootAbs, relativeFile);
  if (!fileAbs) return undefined;
  try {
    const stat = await fs.lstat(fileAbs);
    if (!stat.isFile() || stat.isSymbolicLink()) return undefined;
    const real = await fs.realpath(fileAbs);
    return isInside(rootReal, real) ? real : undefined;
  } catch {
    return undefined;
  }
}

export async function remediateCriticalFindings(
  root: string,
  report: Report,
  removeSource = false,
): Promise<RemediationResult> {
  const critical = report.findings.filter(
    (finding) => finding.severity === "critical" && !finding.baselined && !finding.allowlisted,
  );
  const taskTargets = new Map<string, Map<number, string>>();
  for (const finding of critical.filter((item) => item.ruleId === "RS-VSC-001")) {
    const entry = finding.evidence.find((evidence) => evidence.startsWith("task entry: "));
    const behavior = finding.evidence.find((evidence) => evidence.startsWith("behavior: "))?.slice(10);
    const index = entry ? Number(entry.slice(12)) : NaN;
    if (!Number.isInteger(index) || index < 1 || !behavior) continue;
    const targets = taskTargets.get(finding.file) ?? new Map<number, string>();
    targets.set(index, behavior);
    taskTargets.set(finding.file, targets);
  }
  const packageScripts = new Map<string, Set<string>>();
  for (const finding of critical.filter(
    (item) => item.ruleId === "RS-PKG-001" && item.file.toLowerCase().endsWith("package.json"),
  )) {
    const script = finding.evidence.find((evidence) => evidence.startsWith("script: "))?.slice(8);
    if (!script) continue;
    const names = packageScripts.get(finding.file) ?? new Set<string>();
    names.add(script);
    packageScripts.set(finding.file, names);
  }

  const sourceFilesPreview = [
    ...new Set(
      critical
        .filter((finding) => SOURCE_EXTENSIONS.has(path.extname(finding.file).toLowerCase()))
        .map((finding) => finding.file),
    ),
  ].sort();

  const rootAbs = path.resolve(root);
  const rootReal = await fs.realpath(rootAbs);
  let taskEntriesRemoved = 0;
  let packageScriptsRemoved = 0;

  for (const [relativeFile, targets] of taskTargets) {
    if (!/(^|\/)\.vscode\/tasks\.json$/i.test(relativeFile)) continue;
    const fileReal = await regularFileInsideRoot(rootAbs, rootReal, relativeFile);
    if (!fileReal) continue;
    const original = await fs.readFile(fileReal, "utf8");
    const inspection = inspectVSCodeTasks(relativeFile, original);
    const indexes = inspection.findings.flatMap((finding, index) => {
      const entry = finding.evidence.find((evidence) => evidence.startsWith("task entry: "));
      const behavior = finding.evidence.find((evidence) => evidence.startsWith("behavior: "))?.slice(10);
      const taskIndex = entry ? Number(entry.slice(12)) : NaN;
      return targets.get(taskIndex) === behavior && Number.isInteger(taskIndex)
        ? [inspection.suspiciousIndexes[index] as number]
        : [];
    });
    if (indexes.length === 0) continue;

    let updated = original;
    for (const index of [...indexes].sort((a, b) => b - a)) {
      const edits = modify(updated, ["tasks", index], undefined, {
        formattingOptions: { insertSpaces: true, tabSize: 2, eol: original.includes("\r\n") ? "\r\n" : "\n" },
      });
      updated = applyEdits(updated, edits);
    }
    if (updated !== original) {
      await fs.writeFile(fileReal, updated, "utf8");
      taskEntriesRemoved += indexes.length;
    }
  }

  for (const [relativeFile, names] of packageScripts) {
    const fileReal = await regularFileInsideRoot(rootAbs, rootReal, relativeFile);
    if (!fileReal) continue;
    const original = await fs.readFile(fileReal, "utf8");
    let updated = original;
    for (const name of names) {
      const edits = modify(updated, ["scripts", name], undefined, {
        formattingOptions: formattingOptions(original),
      });
      if (edits.length === 0) continue;
      updated = applyEdits(updated, edits);
      packageScriptsRemoved++;
    }
    if (updated !== original) await fs.writeFile(fileReal, updated, "utf8");
  }

  let sourceFilesRemoved = 0;
  if (removeSource) {
    for (const relativeFile of sourceFilesPreview) {
      const fileReal = await regularFileInsideRoot(rootAbs, rootReal, relativeFile);
      if (!fileReal) continue;
      await fs.unlink(fileReal);
      sourceFilesRemoved++;
    }
  }

  return { taskEntriesRemoved, packageScriptsRemoved, sourceFilesPreview, sourceFilesRemoved };
}
