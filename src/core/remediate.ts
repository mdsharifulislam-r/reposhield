import fs from "node:fs/promises";
import path from "node:path";
import { applyEdits, modify } from "jsonc-parser";
import { inspectVSCodeTasks } from "../rules/vscode.js";
import type { Report } from "./types.js";
import { isInside } from "./options.js";

export async function removeFlaggedVSCodeTasks(root: string, report: Report): Promise<number> {
  const flaggedFiles = new Set(
    report.findings
      .filter(
        (finding) =>
          finding.ruleId === "RS-VSC-001" &&
          finding.severity === "critical" &&
          !finding.baselined &&
          !finding.allowlisted,
      )
      .map((finding) => finding.file),
  );
  if (flaggedFiles.size === 0) return 0;

  const rootAbs = path.resolve(root);
  const rootReal = await fs.realpath(rootAbs);
  let removed = 0;

  for (const relativeFile of flaggedFiles) {
    if (!/(^|\/)\.vscode\/tasks\.json$/i.test(relativeFile)) continue;
    const fileAbs = path.resolve(rootAbs, relativeFile);
    if (!isInside(rootAbs, fileAbs)) continue;

    let fileReal: string;
    try {
      fileReal = await fs.realpath(fileAbs);
      const stat = await fs.lstat(fileAbs);
      if (stat.isSymbolicLink() || !stat.isFile() || !isInside(rootReal, fileReal)) continue;
    } catch {
      continue;
    }

    const original = await fs.readFile(fileReal, "utf8");
    const inspection = inspectVSCodeTasks(relativeFile, original);
    if (inspection.suspiciousIndexes.length === 0) continue;

    let updated = original;
    for (const index of [...inspection.suspiciousIndexes].sort((a, b) => b - a)) {
      const edits = modify(updated, ["tasks", index], undefined, {
        formattingOptions: { insertSpaces: true, tabSize: 2, eol: original.includes("\r\n") ? "\r\n" : "\n" },
      });
      updated = applyEdits(updated, edits);
    }
    if (updated !== original) {
      await fs.writeFile(fileReal, updated, "utf8");
      removed += inspection.suspiciousIndexes.length;
    }
  }

  return removed;
}
