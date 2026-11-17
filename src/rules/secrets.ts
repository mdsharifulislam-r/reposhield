import { redactValue } from "../core/redact.js";
import type { Confidence, Severity } from "../core/types.js";
import { shannonEntropy } from "../analyzers/helpers.js";
import { loc, type RawFinding, type RuleMeta } from "./types.js";

interface SecretPattern {
  kind: string;
  label: string;
  re: RegExp;
  severity: Severity;
  confidence: Confidence;
  /** Capture group holding the secret value (0 = whole match). */
  group?: number;
  /** Minimum Shannon entropy of the value; filters placeholders. */
  minEntropy?: number;
}

const PATTERNS: SecretPattern[] = [
  {
    kind: "private-key",
    label: "private key block",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    severity: "high",
    confidence: "high",
  },
  {
    kind: "aws-access-key",
    label: "AWS access key ID",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    severity: "high",
    confidence: "high",
    minEntropy: 3,
  },
  {
    kind: "github-token",
    label: "GitHub token",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
    severity: "high",
    confidence: "high",
  },
  {
    kind: "npm-token",
    label: "npm access token",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: "high",
    confidence: "high",
  },
  {
    kind: "slack-token",
    label: "Slack token",
    re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    severity: "high",
    confidence: "high",
  },
  {
    kind: "stripe-key",
    label: "Stripe live key",
    re: /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g,
    severity: "high",
    confidence: "high",
  },
  {
    kind: "google-api-key",
    label: "Google API key",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "medium",
    confidence: "high",
  },
  {
    kind: "anthropic-key",
    label: "Anthropic API key",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    severity: "high",
    confidence: "high",
  },
  {
    kind: "openai-key",
    label: "OpenAI API key",
    re: /\bsk-proj-[A-Za-z0-9_-]{32,}\b/g,
    severity: "high",
    confidence: "high",
  },
  {
    kind: "webhook-url",
    label: "chat webhook URL",
    re: /https:\/\/(?:hooks\.slack\.com\/services\/[A-Z0-9/]{20,}|discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]{20,})/g,
    severity: "medium",
    confidence: "high",
  },
  {
    kind: "url-credentials",
    label: "credentials embedded in a URL",
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"`]{1,64}:([^\s:@/'"`]{6,})@[^\s'"`/]+/gi,
    group: 1,
    severity: "medium",
    confidence: "medium",
    minEntropy: 2.5,
  },
  {
    kind: "credential-assignment",
    label: "hard-coded credential",
    re: /\b[\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|auth[_-]?key|private[_-]?key|access[_-]?key)[\w.-]*["']?\s*[:=]\s*["']([^"'\s]{12,})["']/gi,
    group: 1,
    severity: "medium",
    confidence: "low",
    minEntropy: 3.4,
  },
];

const PLACEHOLDER =
  /(example|placeholder|changeme|change[_-]?me|your[_-]?|<[^>]+>|\$\{|\{\{|xxxx|\*{4}|dummy|sample|test|fake|process\.env|env\.)/i;

export const SECRET_RULE_META: RuleMeta = {
  id: "RS-SEC-001",
  title: "Possible hard-coded secret",
  category: "secret",
  severity: "high",
  description:
    "API keys, tokens, private keys, and credential assignments. Values are always redacted in reports; only the type, file and location are recorded.",
};

export interface SecretMatch {
  kind: string;
  label: string;
  severity: Severity;
  confidence: Confidence;
  line: number;
  column: number;
  value: string;
}

/** Find likely secrets in text. Pure; never logs the value. */
export function findSecrets(text: string): SecretMatch[] {
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineOf = (idx: number): { line: number; column: number } => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((lineStarts[mid] as number) <= idx) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: idx - (lineStarts[lo] as number) + 1 };
  };

  const out: SecretMatch[] = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    for (let m = p.re.exec(text); m; m = p.re.exec(text)) {
      if (m[0].length === 0) p.re.lastIndex++;
      const value = m[p.group ?? 0] ?? m[0];
      if (PLACEHOLDER.test(value)) continue;
      if (p.minEntropy !== undefined && shannonEntropy(value) < p.minEntropy) continue;
      const pos = lineOf(m.index);
      out.push({
        kind: p.kind,
        label: p.label,
        severity: p.severity,
        confidence: p.confidence,
        value,
        ...pos,
      });
    }
  }
  // Deduplicate overlapping matches on the same line; keep the most specific (first-declared) kind.
  const seen = new Set<string>();
  return out
    .sort((a, b) => a.line - b.line || a.column - b.column)
    .filter((m) => {
      const key = `${m.line}`;
      const k2 = `${key}:${m.value.slice(0, 8)}`;
      if (seen.has(k2)) return false;
      seen.add(k2);
      return true;
    });
}

/** Replace anything that looks like a secret in free text (e.g. a diff excerpt) with a redacted form. */
export function redactText(text: string): string {
  let out = text;
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    out = out.replace(p.re, (whole, ...groups: unknown[]) => {
      const g = p.group ? (groups[p.group - 1] as string | undefined) : undefined;
      const value = g ?? whole;
      if (PLACEHOLDER.test(value)) return whole;
      if (p.minEntropy !== undefined && shannonEntropy(value) < p.minEntropy) return whole;
      return g ? whole.replace(g, redactValue(g)) : redactValue(whole);
    });
  }
  return out;
}

/** Scan a text file for secrets. Evidence never includes more than a redacted prefix. */
export function secretFindings(file: string, text: string, sensitiveLocation: boolean): RawFinding[] {
  const ordinals = new Map<string, number>();
  return findSecrets(text).map<RawFinding>((m) => {
    const n = (ordinals.get(m.kind) ?? 0) + 1;
    ordinals.set(m.kind, n);
    return {
      ruleId: SECRET_RULE_META.id,
      title: `Possible ${m.label}`,
      category: "secret",
      severity: m.severity,
      confidence: m.confidence,
      file,
      location: loc({ line: m.line, column: m.column }),
      message: `A value that looks like a ${m.label} is committed to the repository. Anyone with read access to the repository (or its history) can use it.`,
      evidence: [`type: ${m.label}`, `value: ${redactValue(m.value)}`],
      recommendation:
        "Revoke or rotate this credential, remove it from the code and from git history, and load it from a secret manager or environment instead.",
      key: `secret|${m.kind}|${n}`,
      ...(sensitiveLocation ? { sensitiveLocation: true } : {}),
    };
  });
}
