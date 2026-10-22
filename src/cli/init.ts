import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { applyEdits, modify } from "jsonc-parser";
import { VERSION } from "../core/version.js";

const ORIGINAL_PREFIX = "reposhield:init:original:";
const BOOTSTRAP_FILE = "reposhield-bootstrap.ts";

export interface InitPreview {
  scripts: string[];
  createsBootstrap: boolean;
  addsDependency: boolean;
  alreadyConfigured: boolean;
}

function formattingOptions(text: string): { insertSpaces: boolean; tabSize: number; eol: string } {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const match = text.match(/\r?\n([ \t]+)"/);
  const whitespace = match?.[1] ?? "  ";
  return {
    insertSpaces: !whitespace.includes("\t"),
    tabSize: whitespace.includes("\t") ? 2 : whitespace.length,
    eol,
  };
}

function edit(text: string, jsonPath: (string | number)[], value: unknown): string {
  return applyEdits(text, modify(text, jsonPath, value, { formattingOptions: formattingOptions(text) }));
}

function bootstrapSource(serverEntry: string): string {
  const importPath = `./${serverEntry.replace(/\\/g, "/").replace(/\.ts$/, ".js")}`;
  return `import { clean, generateReport } from "reposhield-scan";\n\nconst report = await clean({ root: process.cwd(), mode: "ci", failOn: "high" });\nprocess.stderr.write(generateReport(report, { format: "text" }));\n\nif (!report.safe) process.exit(1);\nawait import(${JSON.stringify(importPath)});\n`;
}

export async function inspectInit(root: string): Promise<InitPreview> {
  const rootAbs = path.resolve(root);
  const packagePath = path.join(rootAbs, "package.json");
  const packageStat = await fs.lstat(packagePath);
  if (!packageStat.isFile() || packageStat.isSymbolicLink())
    throw new Error("package.json must be a regular file inside the project root.");
  const text = await fs.readFile(packagePath, "utf8");
  let pkg: unknown;
  try {
    pkg = JSON.parse(text);
  } catch {
    throw new Error("package.json is not valid JSON.");
  }
  if (!pkg || typeof pkg !== "object" || Array.isArray(pkg))
    throw new Error("package.json must contain a JSON object.");

  const packageObject = pkg as Record<string, unknown>;
  const scripts = packageObject.scripts;
  if (scripts !== undefined && (!scripts || typeof scripts !== "object" || Array.isArray(scripts)))
    throw new Error("package.json scripts must be an object.");
  const scriptObject = (scripts ?? {}) as Record<string, unknown>;
  const names = Object.keys(scriptObject).filter((name) => {
    if (name.startsWith(ORIGINAL_PREFIX)) return false;
    return true;
  });
  const pending = names.filter((name) => {
    const originalName = `${ORIGINAL_PREFIX}${name}`;
    const command = scriptObject[name];
    if (typeof command !== "string") throw new Error(`Cannot initialize non-string npm script ${name}.`);
    const wrapper = command.includes(` run -- npm --ignore-scripts run ${originalName}`);
    if (!wrapper) return true;
    if (typeof scriptObject[originalName] !== "string")
      throw new Error(`Cannot update wrapper: original script ${originalName} is missing.`);
    return !command.includes(`reposhield-scan@${VERSION} run -- npm --ignore-scripts run ${originalName}`);
  });

  for (const name of pending) {
    const originalName = `${ORIGINAL_PREFIX}${name}`;
    const command = scriptObject[name];
    const alreadyWrapped =
      typeof command === "string" && command.includes(` run -- npm --ignore-scripts run ${originalName}`);
    if (!alreadyWrapped && Object.hasOwn(scriptObject, originalName))
      throw new Error(`Cannot initialize: script key ${originalName} already exists.`);
  }

  const serverEntry = ["server.ts", path.join("src", "server.ts")].find((candidate) =>
    existsSync(path.join(rootAbs, candidate)),
  );
  const bootstrapPath = path.join(rootAbs, BOOTSTRAP_FILE);
  const bootstrapExists = serverEntry ? existsSync(bootstrapPath) : false;
  const createsBootstrap = Boolean(serverEntry && !bootstrapExists);
  const dependencyObject = packageObject.dependencies;
  if (
    dependencyObject !== undefined &&
    (!dependencyObject || typeof dependencyObject !== "object" || Array.isArray(dependencyObject))
  ) {
    throw new Error("package.json dependencies must be an object.");
  }
  const addsDependency =
    createsBootstrap && !("reposhield-scan" in ((dependencyObject ?? {}) as Record<string, unknown>));

  return {
    scripts: pending,
    createsBootstrap,
    addsDependency,
    alreadyConfigured: pending.length === 0 && !createsBootstrap && !addsDependency,
  };
}

function existsSync(file: string): boolean {
  try {
    const stat = fsSync.lstatSync(file);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

export async function applyInit(root: string): Promise<InitPreview> {
  const rootAbs = path.resolve(root);
  const result = await inspectInit(rootAbs);
  if (result.alreadyConfigured) return result;

  const packagePath = path.join(rootAbs, "package.json");
  let text = await fs.readFile(packagePath, "utf8");
  const pkg = JSON.parse(text) as Record<string, unknown>;
  const scripts = (pkg.scripts ?? {}) as Record<string, unknown>;

  for (const name of result.scripts) {
    const originalName = `${ORIGINAL_PREFIX}${name}`;
    const originalCommand = scripts[name];
    const alreadyWrapped =
      typeof originalCommand === "string" &&
      originalCommand.includes(` run -- npm --ignore-scripts run ${originalName}`);
    if (!alreadyWrapped) text = edit(text, ["scripts", originalName], originalCommand);
    const wrapper = `npx --yes reposhield-scan@${VERSION} run -- npm --ignore-scripts run ${originalName}`;
    text = edit(text, ["scripts", name], wrapper);
  }

  if (result.addsDependency) {
    text = edit(text, ["dependencies", "reposhield-scan"], VERSION);
  }

  const serverEntry = ["server.ts", path.join("src", "server.ts")].find((candidate) =>
    existsSync(path.join(rootAbs, candidate)),
  );
  if (result.createsBootstrap && serverEntry) {
    await fs.writeFile(path.join(rootAbs, BOOTSTRAP_FILE), bootstrapSource(serverEntry), { flag: "wx" });
  }
  if (text !== (await fs.readFile(packagePath, "utf8"))) await fs.writeFile(packagePath, text, "utf8");
  return result;
}
