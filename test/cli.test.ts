import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { EXIT, main, type CliIO } from "../src/cli/main.js";
import { fake, fixture, project, tmpDir } from "./helpers/project.js";

async function run(args: string[], cwd: string): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const io: CliIO = { stdout: (s) => (out += s), stderr: (s) => (err += s), cwd, env: {}, isTTY: false };
  const code = await main(args, io);
  return { code, out, err };
}

const bad = (): string => project({ "src/run.js": fixture("malicious/shell-pipe.js.txt") });
const good = (): string => project({ "src/ok.js": fixture("benign/plain.js.txt") });

describe("CLI exit codes", () => {
  it("audit mode reports findings but exits 0", async () => {
    const r = await run(["scan"], bad());
    expect(r.code).toBe(EXIT.OK);
    expect(r.out).toContain("FAIL");
    expect(r.out).toContain("RS-PROC-002");
  });

  it("strict and ci modes exit 1 on policy violations", async () => {
    expect((await run(["scan", "--mode", "strict"], bad())).code).toBe(EXIT.POLICY);
    expect((await run(["scan", "--mode", "ci"], bad())).code).toBe(EXIT.POLICY);
  });

  it("--fail-on makes audit mode enforce", async () => {
    expect((await run(["scan", "--fail-on", "high"], bad())).code).toBe(EXIT.POLICY);
    expect((await run(["scan", "--fail-on", "critical"], good())).code).toBe(EXIT.OK);
  });

  it("clean repositories exit 0 in every mode", async () => {
    const root = good();
    for (const mode of ["audit", "strict", "ci"])
      expect((await run(["scan", "--mode", mode], root)).code).toBe(EXIT.OK);
  });

  it("usage and configuration errors exit 2 with a message", async () => {
    const root = good();
    for (const args of [
      ["scan", "--mode", "turbo"],
      ["scan", "--format", "xml"],
      ["scan", "--nope"],
      ["frobnicate"],
      ["scan", "--root", "/not/here"],
      ["baseline"],
      ["scan", "--changed", "--mode", "ci"],
      ["scan", "--max-file-size", "abc"],
    ]) {
      const r = await run(args, root);
      expect(r.code, args.join(" ")).toBe(EXIT.USAGE);
      expect(r.err).toMatch(/reposhield:/);
    }
  });

  it("--help and --version work", async () => {
    const h = await run(["--help"], good());
    expect(h.code).toBe(0);
    expect(h.out).toMatch(/EXIT CODES/);
    expect(h.out).toMatch(/never executes scanned code/);
    const v = await run(["--version"], good());
    expect(v.out.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe("CLI output formats", () => {
  it("emits valid JSON with the documented shape", async () => {
    const r = await run(["scan", "--format", "json", "--mode", "ci"], bad());
    const j = JSON.parse(r.out);
    expect(j.tool.name).toBe("reposhield");
    expect(j.safe).toBe(false);
    expect(Array.isArray(j.findings)).toBe(true);
    expect(j.findings[0]).toEqual(
      expect.objectContaining({
        ruleId: expect.any(String),
        severity: expect.any(String),
        confidence: expect.any(String),
        file: expect.any(String),
        recommendation: expect.any(String),
        fingerprint: expect.any(String),
      }),
    );
    expect(j.generatedAt).toBeUndefined();
  });

  it("emits valid SARIF 2.1.0", async () => {
    const root = project({
      "src/run.js": fixture("malicious/shell-pipe.js.txt"),
      "src/k.js": `const t = "${fake.github()}";\n`,
    });
    const r = await run(["scan", "--format", "sarif"], root);
    const s = JSON.parse(r.out);
    expect(s.version).toBe("2.1.0");
    expect(s.$schema).toMatch(/sarif/);
    const run0 = s.runs[0];
    expect(run0.tool.driver.name).toBe("RepoShield");
    expect(run0.results.length).toBeGreaterThan(1);
    const ruleIds = new Set(run0.tool.driver.rules.map((x: { id: string }) => x.id));
    for (const res of run0.results) {
      expect(ruleIds.has(res.ruleId)).toBe(true);
      expect(run0.tool.driver.rules[res.ruleIndex].id).toBe(res.ruleId);
      expect(["error", "warning", "note"]).toContain(res.level);
      const loc = res.locations[0].physicalLocation;
      expect(loc.artifactLocation.uri).not.toMatch(/^\//);
      expect(loc.region.startLine).toBeGreaterThanOrEqual(1);
      expect(res.partialFingerprints["reposhieldFingerprint/v1"]).toMatch(/^[0-9a-f]+$/);
    }
    expect(r.out).not.toContain(fake.github());
  });

  it("writes reports to --output and keeps stdout clean", async () => {
    const dir = tmpDir();
    const r = await run(["scan", "--format", "json", "--output", "out/report.json", "--root", bad()], dir);
    expect(r.out).toBe("");
    expect(
      JSON.parse(fs.readFileSync(path.join(dir, "out/report.json"), "utf8")).findings.length,
    ).toBeGreaterThan(0);
  });

  it("text output shows severity, confidence, file and line without color when not a TTY", async () => {
    const r = await run(["scan"], bad());
    expect(r.out).toMatch(/\[CRITICAL\] RS-PROC-002/);
    expect(r.out).toMatch(/src\/run\.js/);
    expect(r.out).toMatch(/\d+:\d+\s+confidence: high/);
    // eslint-disable-next-line no-control-regex
    expect(r.out).not.toMatch(/\u001b\[/);
  });
});

describe("CLI commands", () => {
  it("init previews by default, then preserves and gates existing scripts with --yes", async () => {
    const packageText = JSON.stringify(
      {
        name: "sample-app",
        scripts: {
          prebuild: "node before.js",
          build: "node api.js && tsc -b && vite build",
          postbuild: "node after.js",
          dev: "node api.js && vite",
          start: "node dist/server.js",
          test: "vitest run",
          lint: "eslint .",
          api: "node api.js",
          "custom-build": "node api.js && vite build",
          postinstall: "node postinstall-check.js",
          prepublishOnly: "node release-check.js",
          prepack: "node pack-check.js",
        },
      },
      null,
      2,
    );
    const root = project({ "package.json": packageText, "server.ts": "export {};\n" });

    const preview = await run(["init", "--root", root], root);
    expect(preview.code).toBe(EXIT.OK);
    expect(preview.out).toMatch(/preview/i);
    expect(fs.readFileSync(path.join(root, "package.json"), "utf8")).toBe(packageText);
    expect(fs.existsSync(path.join(root, "reposhield-bootstrap.ts"))).toBe(false);

    const applied = await run(["init", "--root", root, "--yes"], root);
    expect(applied.code).toBe(EXIT.OK);
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    expect(pkg.scripts["reposhield:init:original:prebuild"]).toBe("node before.js");
    expect(pkg.scripts["reposhield:init:original:build"]).toBe("node api.js && tsc -b && vite build");
    expect(pkg.scripts.build).toMatch(/reposhield-scan@\d+\.\d+\.\d+ run -- npm --ignore-scripts run/);
    expect(pkg.scripts.dev).toMatch(/reposhield-scan@\d+\.\d+\.\d+ run -- npm --ignore-scripts run/);
    expect(pkg.scripts["reposhield:init:original:postbuild"]).toBe("node after.js");
    expect(pkg.scripts["reposhield:init:original:start"]).toBe("node dist/server.js");
    expect(pkg.scripts["reposhield:init:original:test"]).toBe("vitest run");
    expect(pkg.scripts["reposhield:init:original:lint"]).toBe("eslint .");
    expect(pkg.scripts.api).toMatch(/reposhield-scan@\d+\.\d+\.\d+ run -- npm --ignore-scripts run/);
    expect(pkg.scripts["reposhield:init:original:api"]).toBe("node api.js");
    expect(pkg.scripts["reposhield:init:original:custom-build"]).toBe("node api.js && vite build");
    expect(pkg.scripts.postinstall).toMatch(/reposhield-scan@\d+\.\d+\.\d+ run -- npm --ignore-scripts run/);
    expect(pkg.scripts["reposhield:init:original:postinstall"]).toBe("node postinstall-check.js");
    expect(pkg.scripts["reposhield:init:original:prepublishOnly"]).toBe("node release-check.js");
    expect(pkg.scripts["reposhield:init:original:prepack"]).toBe("node pack-check.js");
    expect(pkg.dependencies["reposhield-scan"]).toMatch(/^\d+\.\d+\.\d+$/);
    const bootstrap = fs.readFileSync(path.join(root, "reposhield-bootstrap.ts"), "utf8");
    expect(bootstrap).toContain("clean(");
    expect(bootstrap).toContain('await import("./server.js")');

    const again = await run(["init", "--root", root, "--yes"], root);
    expect(again.code).toBe(EXIT.OK);
    const second = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    expect(
      Object.keys(second.scripts).filter((name) => name.startsWith("reposhield:init:original:")).length,
    ).toBe(12);
  });

  it("scan --remove deletes only the suspicious VS Code task entry", async () => {
    const root = project({
      ".vscode/tasks.json": `{
        "version": "2.0.0",
        "tasks": [
          { "label": "bad", "type": "shell", "command": "node", "args": ["public/fonts/bad.otf"] },
          { "label": "good", "type": "shell", "command": "npm run build" }
        ]
      }`,
    });
    const r = await run(["scan", "--root", root, "--remove"], root);
    const tasks = fs.readFileSync(path.join(root, ".vscode/tasks.json"), "utf8");
    expect(r.code).toBe(EXIT.OK);
    expect(tasks).not.toContain("bad.otf");
    expect(tasks).toContain("npm run build");
  });

  it("scan --remove previews critical source paths and requires --yes to delete them", async () => {
    const root = project({ "src/loader.js": fixture("malicious/decode-exec.js.txt") });
    const source = path.join(root, "src/loader.js");
    const preview = await run(
      ["scan", "--root", root, "--remove", "--remove-source", "--format", "json"],
      root,
    );
    expect(preview.code).toBe(EXIT.OK);
    expect(fs.existsSync(source)).toBe(true);
    expect(JSON.parse(preview.out).notes.join(" ")).toContain("src/loader.js");

    const applied = await run(
      ["scan", "--root", root, "--remove", "--remove-source", "--yes", "--format", "json"],
      root,
    );
    expect(applied.code).toBe(EXIT.OK);
    expect(fs.existsSync(source)).toBe(false);
    expect(JSON.parse(applied.out).notes.join(" ")).toMatch(/Deleted 1 critical source file/);
  });

  it("run --remove cleans the suspicious task before starting the command", async () => {
    const root = project({
      ".vscode/tasks.json": JSON.stringify({
        version: "2.0.0",
        tasks: [{ label: "bad", type: "shell", command: "node", args: ["public/fonts/bad.otf"] }],
      }),
    });
    const marker = path.join(root, "command-ran");
    const code = `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran")`;
    const r = await run(["run", "--root", root, "--remove", "--", process.execPath, "-e", code], root);
    expect(r.code).toBe(EXIT.OK);
    expect(fs.existsSync(marker)).toBe(true);
    expect(fs.readFileSync(path.join(root, ".vscode/tasks.json"), "utf8")).not.toContain("bad.otf");
  });

  it("run blocks a command when the scan fails policy", async () => {
    const root = bad();
    const marker = path.join(root, "command-ran");
    const code = `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran")`;
    const r = await run(["run", "--root", root, "--", process.execPath, "-e", code], root);
    expect(r.code).toBe(EXIT.POLICY);
    expect(fs.existsSync(marker)).toBe(false);
    expect(r.err).toContain("scan blocked the command, so it was not started");
  });

  it("run starts a passing command and returns its exit code", async () => {
    const root = good();
    const r = await run(["run", "--root", root, "--", process.execPath, "-e", "process.exit(7)"], root);
    expect(r.code).toBe(7);
    expect(r.err).toMatch(/scan passed.*not proof of safety.*Running:/);
  });

  it("run forwards arguments and allows a stricter policy threshold to be overridden", async () => {
    const root = project({ "src/exfil.js": fixture("malicious/exfil.js.txt") });
    const marker = path.join(root, "args.json");
    const code = `require("node:fs").writeFileSync(${JSON.stringify(marker)}, JSON.stringify(process.argv.slice(1)))`;
    const r = await run(
      [
        "run",
        "--root",
        root,
        "--fail-on",
        "critical",
        "--",
        process.execPath,
        "-e",
        code,
        "two words",
        "--flag",
      ],
      root,
    );
    expect(r.code).toBe(EXIT.OK);
    expect(JSON.parse(fs.readFileSync(marker, "utf8"))).toEqual(["two words", "--flag"]);
  });

  it("run rejects missing separators or commands and separators on other commands", async () => {
    const root = good();
    for (const args of [
      ["run", "--"],
      ["run", "next", "build"],
      ["scan", "--", "echo", "no"],
    ]) {
      expect((await run(args, root)).code, args.join(" ")).toBe(EXIT.USAGE);
    }
  });

  it("run returns 127 when the command cannot be started", async () => {
    const root = good();
    const r = await run(["run", "--root", root, "--", "reposhield-command-that-does-not-exist"], root);
    expect(r.code).toBe(127);
  });

  it("baseline create then compare", async () => {
    const root = project({ "src/a.js": fixture("malicious/exfil.js.txt") });
    const c = await run(["baseline", "create"], root);
    expect(c.code).toBe(0);
    expect(c.out).toMatch(/Baseline written/);
    expect((await run(["baseline", "compare"], root)).code).toBe(0);
    fs.writeFileSync(path.join(root, "src/b.js"), fixture("malicious/shell-pipe.js.txt"));
    const cmp = await run(["baseline", "compare"], root);
    expect(cmp.code).toBe(EXIT.POLICY);
    expect(cmp.err).toMatch(/1 new|new,/);
  });

  it("changed mode needs no flags beyond --changed", async () => {
    const r = await run(["scan", "--changed"], bad());
    expect(r.out).toMatch(/mode=changed/);
  });

  it("scans a single file", async () => {
    const root = bad();
    const r = await run(["file", "src/run.js"], root);
    expect(r.out).toContain("RS-PROC-002");
    expect((await run(["file", "../x.js"], root)).code).toBe(EXIT.USAGE);
  });

  it("lists rules", async () => {
    const r = await run(["rules"], good());
    expect(r.out).toMatch(/RS-EXEC-002\s+critical/);
    expect(JSON.parse((await run(["rules", "--format", "json"], good())).out).length).toBeGreaterThan(15);
  });

  it("reads a JSON config file and never executes JavaScript configuration", async () => {
    const root = project({
      "src/run.js": fixture("malicious/shell-pipe.js.txt"),
      ".reposhieldrc.json": JSON.stringify({ disabledRules: ["RS-PROC-002"] }),
    });
    expect((await run(["scan", "--format", "json"], root)).out).not.toMatch(/RS-PROC-002/);
    const evil = project({
      "src/run.js": "export {}",
      "reposhield.config.js": "require('fs').writeFileSync('pwned','x')",
    });
    await run(["scan"], evil);
    expect(fs.existsSync(path.join(evil, "pwned"))).toBe(false);
    const broken = project({ ".reposhieldrc.json": "{" });
    expect((await run(["scan"], broken)).code).toBe(EXIT.USAGE);
  });

  it("monitor starts only on request and stops cleanly on a signal", async () => {
    const root = good();
    let out = "";
    let stop: (() => void) | undefined;
    const io: CliIO = {
      stdout: (s) => (out += s),
      stderr: () => undefined,
      cwd: root,
      env: {},
      isTTY: false,
      onSignal: (h) => {
        stop = () => h("SIGINT");
        return () => undefined;
      },
    };
    const p = main(["monitor", "--interval", "1"], io);
    await new Promise((r) => setTimeout(r, 700));
    expect(out).toMatch(/cycle 1/);
    stop?.();
    expect(await p).toBe(0);
    expect(out).toMatch(/Monitor stopped/);
  });
});
