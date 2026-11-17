import { ConfigError } from "../core/options.js";
import type { Report } from "../core/types.js";
import { renderSarif } from "./sarif.js";
import { renderText, type TextOptions } from "./text.js";

export const FORMATS = ["text", "json", "sarif"] as const;
export type ReportFormat = (typeof FORMATS)[number];

export interface GenerateReportOptions extends TextOptions {
  format?: ReportFormat;
}

/** Render a report. Reports contain redacted evidence only, whatever the format. */
export function generateReport(report: Report, options: GenerateReportOptions = {}): string {
  const format = options.format ?? "text";
  switch (format) {
    case "json":
      return `${JSON.stringify(report, null, 2)}\n`;
    case "sarif":
      return `${renderSarif(report)}\n`;
    case "text":
      return renderText(report, options);
    default:
      throw new ConfigError(
        `Unknown report format "${String(format)}". Expected one of: ${FORMATS.join(", ")}.`,
      );
  }
}

export { renderSarif, renderText };
