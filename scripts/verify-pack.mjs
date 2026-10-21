// Verifies what `npm publish` would ship. Run after `npm run build`.
// Fails when the tarball would contain sources, tests, inert malware fixtures,
// environment files, source maps, or anything that looks like a secret.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  throw new Error("npm CLI path is unavailable; run this script with `npm run verify:pack`.");
}

const raw = execFileSync(process.execPath, [npmCli, "pack", "--dry-run", "--json", "--ignore-scripts"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
});
const [pack] = JSON.parse(raw);
const files = pack.files.map((f) => f.path).sort();

const REQUIRED = [
  "package.json",
  "README.md",
  "dist/index.js",
  "dist/index.cjs",
  "dist/index.d.ts",
  "dist/cli.js",
];
const FORBIDDEN = [
  /^src\//,
  /^test\//,
  /^examples\//,
  /^scripts\//,
  /^\.github\//,
  /fixtures?\//i,
  /(^|\/)\.env/,
  /\.map$/,
  /\.tgz$/,
  /\.pem$|\.key$/,
  /^node_modules\//,
  /^\.reposhield-baseline\.json$/,
];
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bghp_[A-Za-z0-9]{36}\b/,
  /\bnpm_[A-Za-z0-9]{36}\b/,
];

const problems = [];
for (const r of REQUIRED) if (!files.includes(r)) problems.push(`missing required file: ${r}`);
for (const f of files) {
  if (FORBIDDEN.some((re) => re.test(f))) problems.push(`forbidden file in package: ${f}`);
  if (f.startsWith("dist/") || f === "README.md") {
    const text = readFileSync(f, "utf8");
    for (const re of SECRET_PATTERNS) if (re.test(text)) problems.push(`secret-like content in ${f}: ${re}`);
  }
}

console.log(
  `${pack.name}@${pack.version}: ${files.length} files, ${pack.size} bytes packed, ${pack.unpackedSize} unpacked`,
);
for (const f of files) console.log(`  ${f}`);

if (problems.length) {
  console.error("\nPackage verification FAILED:");
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log("\nPackage verification passed.");
