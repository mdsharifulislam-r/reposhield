import { createHash } from "node:crypto";

/**
 * Redact a secret so it can be shown to a human without being reusable.
 * Keeps at most 2 leading characters and the length, never the middle or end.
 */
export function redactValue(value: string): string {
  const v = value.trim();
  if (v.length <= 4) return "[REDACTED]";
  return `${v.slice(0, 2)}…[REDACTED:${v.length} chars]`;
}

/** Collapse whitespace and truncate evidence snippets to a safe, short length. */
export function snippet(text: string, max = 80): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** Stable fingerprint that never embeds the raw text of the evidence. */
export function fingerprint(parts: Array<string | number | undefined>): string {
  const h = createHash("sha256");
  for (const p of parts) {
    h.update(String(p ?? ""));
    h.update("\u0000");
  }
  return h.digest("hex").slice(0, 24);
}

/** Strip control characters so untrusted text cannot manipulate terminal output. */
export function sanitizeForTerminal(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "?");
}
