import { main } from "./main.js";

const code = await main(process.argv.slice(2), {
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
  cwd: process.cwd(),
  env: process.env,
  isTTY: Boolean(process.stdout.isTTY),
  onSignal(handler) {
    const onInterrupt = (): void => handler("SIGINT");
    const onTerminate = (): void => handler("SIGTERM");
    process.on("SIGINT", onInterrupt);
    process.on("SIGTERM", onTerminate);
    return () => {
      process.off("SIGINT", onInterrupt);
      process.off("SIGTERM", onTerminate);
    };
  },
});
process.exitCode = code;
