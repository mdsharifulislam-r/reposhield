import { main } from "./main.js";

const code = await main(process.argv.slice(2), {
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
  cwd: process.cwd(),
  env: process.env,
  isTTY: Boolean(process.stdout.isTTY),
  onSignal(handler) {
    process.on("SIGINT", handler);
    process.on("SIGTERM", handler);
    return () => {
      process.off("SIGINT", handler);
      process.off("SIGTERM", handler);
    };
  },
});
process.exitCode = code;
