import { findNodeAtLocation, getNodeValue, parseTree } from "jsonc-parser";
import type { RawFinding, RuleMeta } from "./types.js";
import { loc } from "./types.js";

export const VSCODE_TASK_RULE_META: RuleMeta = {
  id: "RS-VSC-001",
  title: "VS Code task executes a suspicious payload",
  category: "process-execution",
  severity: "critical",
  description:
    "A VS Code task executes a font asset as code, downloads and executes remote content, or runs an encoded command.",
};

export interface VSCodeTaskInspection {
  findings: RawFinding[];
  suspiciousIndexes: number[];
}

const FONT_AS_CODE =
  /(?:^|[;&|({]\s*)(?:node(?:\.exe)?|nodejs|bun|deno|python(?:3(?:\.\d+)?)?(?:\.exe)?|ruby|perl)(?:\s+--?[\w-]+(?:=\S+)?)*\s+["']?(?:\.{1,2}[\\/]|[A-Za-z]:[\\/]|\/)?[^\s"';&|<>]+\.(?:otf|ttf|ttc|woff2?|eot|fon)(?=$|[\s"';&|<>])/i;
const DOWNLOAD_EXEC =
  /\b(?:curl|wget|invoke-webrequest|downloadstring|start-bitstransfer)\b[\s\S]{0,240}?(?:\|\s*(?:sh|bash|node|python)|&&\s*(?:sh|bash|node|python)|\b(?:iex|invoke-expression)\b)/i;
const ENCODED_COMMAND =
  /\b(?:powershell(?:\.exe)?|pwsh|bash|sh|node(?:\.exe)?)\b[\s\S]{0,140}?(?:\s-enc(?:odedcommand)?\b|frombase64string|base64\s+(?:-d|--decode)\b)/i;

function taskCommand(task: unknown): { command: string; label?: string } | undefined {
  if (!task || typeof task !== "object" || Array.isArray(task)) return undefined;
  const value = task as Record<string, unknown>;
  if (typeof value.command !== "string") return undefined;
  const args = Array.isArray(value.args)
    ? value.args.filter((arg): arg is string => typeof arg === "string")
    : [];
  return {
    command: [value.command, ...args].join(" "),
    ...(typeof value.label === "string" ? { label: value.label } : {}),
  };
}

function taskRisk(command: string): "font-as-code" | "download-exec" | "encoded-command" | undefined {
  if (FONT_AS_CODE.test(command)) return "font-as-code";
  if (DOWNLOAD_EXEC.test(command)) return "download-exec";
  if (ENCODED_COMMAND.test(command)) return "encoded-command";
  return undefined;
}

export function inspectVSCodeTasks(file: string, text: string): VSCodeTaskInspection {
  const errors: Parameters<typeof parseTree>[1] = [];
  const tree = parseTree(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (!tree || errors.length > 0) return { findings: [], suspiciousIndexes: [] };

  const tasksNode = findNodeAtLocation(tree, ["tasks"]);
  if (tasksNode?.type !== "array") return { findings: [], suspiciousIndexes: [] };

  const findings: RawFinding[] = [];
  const suspiciousIndexes: number[] = [];
  for (const [index, taskNode] of (tasksNode.children ?? []).entries()) {
    const task = taskCommand(getNodeValue(taskNode));
    if (!task) continue;
    const risk = taskRisk(task.command);
    if (!risk) continue;

    suspiciousIndexes.push(index);
    const line = text.slice(0, taskNode.offset).split("\n").length;
    const description =
      risk === "font-as-code"
        ? "a font asset is passed to a code interpreter"
        : risk === "download-exec"
          ? "remote content is downloaded and passed to an interpreter"
          : "an encoded command is passed to an interpreter";
    findings.push({
      ruleId: VSCODE_TASK_RULE_META.id,
      title: VSCODE_TASK_RULE_META.title,
      category: VSCODE_TASK_RULE_META.category,
      severity: "critical",
      confidence: "high",
      file,
      sensitiveLocation: true,
      location: loc({ line, column: 1 }),
      message: `A VS Code task contains a high-risk execution pattern: ${description}.`,
      evidence: [`task entry: ${index + 1}`, `behavior: ${risk}`],
      recommendation:
        "Disable the task and verify its source before running build commands. The opt-in --remove action removes only matching task entries; review the diff afterward.",
      key: `vscode-task|${risk}`,
    });
  }

  return { findings, suspiciousIndexes };
}
