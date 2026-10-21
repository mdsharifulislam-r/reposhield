import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: false,
    clean: false,
    target: "node18",
    splitting: false,
    outExtension: ({ format }) => ({ js: format === "cjs" ? ".cjs" : ".js" }),
  },
  {
    entry: { cli: "src/cli/bin.ts" },
    format: ["esm"],
    dts: false,
    sourcemap: false,
    clean: false,
    target: "node18",
    splitting: false,
    banner: { js: "#!/usr/bin/env node" },
  },
]);
