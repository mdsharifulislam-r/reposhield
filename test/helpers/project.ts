import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach } from "vitest";

const FIXTURES = path.resolve(__dirname, "../fixtures");
const dirs: string[] = [];

afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

/** Read an inert fixture (stored as `.txt` so it is never a runnable source file). */
export function fixture(name: string): string {
  return fs.readFileSync(path.join(FIXTURES, name), "utf8");
}

export function tmpDir(prefix = "reposhield-"): string {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  dirs.push(d);
  return d;
}

export function write(root: string, rel: string, content: string): void {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

/** Create a temp project from a map of relative path -> content. */
export function project(files: Record<string, string> = {}): string {
  const root = tmpDir();
  for (const [rel, content] of Object.entries(files)) write(root, rel, content);
  return root;
}

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "Test",
  GIT_AUTHOR_EMAIL: "test@example.invalid",
  GIT_COMMITTER_NAME: "Test",
  GIT_COMMITTER_EMAIL: "test@example.invalid",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
};

export function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", ...args], {
    cwd,
    env: GIT_ENV,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

export function initRepo(root: string): void {
  git(root, "init", "-q");
}

export function commitAll(root: string, message = "commit"): string {
  git(root, "add", "-A");
  git(root, "commit", "-q", "--no-verify", "-m", message);
  return git(root, "rev-parse", "HEAD").trim();
}

/** Hash everything under root (including .git) so tests can prove a scan changed nothing. */
export function snapshot(root: string): string {
  const h = createHash("sha256");
  const walk = (dir: string): void => {
    for (const name of fs.readdirSync(dir).sort()) {
      const abs = path.join(dir, name);
      const st = fs.lstatSync(abs);
      const rel = path.relative(root, abs);
      if (st.isDirectory()) {
        h.update(`d:${rel}\n`);
        walk(abs);
      } else if (st.isSymbolicLink()) {
        h.update(`l:${rel}:${fs.readlinkSync(abs)}\n`);
      } else {
        h.update(`f:${rel}:`);
        h.update(fs.readFileSync(abs));
      }
    }
  };
  walk(root);
  return h.digest("hex");
}

/** Build a likely-fake secret at runtime so no secret-shaped literal is committed to this repo. */
export const fake = {
  github: (): string => `ghp_${"aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"}`,
  aws: (): string => `AKIA${"Q7Z4X9M2K5R8T1V3"}`,
  slack: (): string => `xoxb-${"1234567890-abcdefghijKLMNOP"}`,
  privateKeyHeader: (): string => `-----BEGIN ${"RSA"} PRIVATE KEY-----`,
};
