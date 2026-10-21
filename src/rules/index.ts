import { JS_RULES } from "./js-rules.js";
import { PACKAGE_RULE_META } from "./package.js";
import { SECRET_RULE_META } from "./secrets.js";
import type { RuleMeta } from "./types.js";

export const SCAN_RULE_META: RuleMeta[] = [
  {
    id: "RS-SCAN-001",
    title: "File could not be parsed",
    category: "scan-error",
    severity: "low",
    description:
      "Syntax RepoShield could not parse. Unanalyzable code cannot be checked, and broken syntax is occasionally used to evade scanners. Weighted higher in config files and strict/ci modes.",
  },
  {
    id: "RS-SCAN-002",
    title: "File too large to analyze",
    category: "scan-error",
    severity: "medium",
    description:
      "A source file exceeded maxFileSizeBytes and was not analyzed. Padding a file past the limit is a known evasion technique; raise the limit or review the file manually.",
  },
  {
    id: "RS-BASE-001",
    title: "Baseline file changed",
    category: "baseline",
    severity: "medium",
    description:
      "The accepted-findings baseline was modified relative to the base reference. Review what was newly accepted.",
  },
];

export const ALL_RULES: RuleMeta[] = [
  ...JS_RULES.map(({ id, title, category, severity, description }) => ({
    id,
    title,
    category,
    severity,
    description,
  })),
  SECRET_RULE_META,
  ...PACKAGE_RULE_META,
  ...SCAN_RULE_META,
].sort((a, b) => (a.id < b.id ? -1 : 1));

export { JS_RULES };
