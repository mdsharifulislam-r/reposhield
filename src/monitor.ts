import type { RepoShieldOptions } from "./core/options.js";
import { runScan } from "./core/scanner.js";
import type { Finding, Report } from "./core/types.js";
import { isActive } from "./core/scoring.js";

export interface MonitorHandlers {
  /** Called after every scan. `newFindings` are active findings not present in the previous cycle. */
  onReport?(report: Report, info: { cycle: number; newFindings: Finding[] }): void | Promise<void>;
  onError?(error: Error, info: { cycle: number }): void;
}

export interface MonitorHandle {
  /** Stop after the in-flight scan (which is aborted) and resolve once fully stopped. */
  stop(): Promise<void>;
  /** Resolves when the monitor has stopped. */
  done: Promise<void>;
}

/**
 * Re-scan on a fixed interval. Never started implicitly: you must call it.
 * Scans never overlap, and stop() / an aborted signal ends the loop cleanly.
 */
export function monitor(options: RepoShieldOptions = {}, handlers: MonitorHandlers = {}): MonitorHandle {
  const interval = Math.max(1000, options.monitorIntervalMs ?? 30_000);
  const controller = new AbortController();
  options.signal?.addEventListener("abort", () => controller.abort(), { once: true });
  let timer: NodeJS.Timeout | undefined;
  let wake: (() => void) | undefined;
  let previous = new Set<string>();

  const sleep = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      wake = resolve;
      timer = setTimeout(resolve, ms);
      timer.unref?.();
    });

  const loop = async (): Promise<void> => {
    for (let cycle = 1; !controller.signal.aborted; cycle++) {
      try {
        const { report } = await runScan({
          ...options,
          mode: options.mode ?? "audit",
          signal: controller.signal,
        });
        const active = report.findings.filter(isActive);
        const fresh = cycle === 1 ? [] : active.filter((f) => !previous.has(f.fingerprint));
        previous = new Set(active.map((f) => f.fingerprint));
        await handlers.onReport?.(report, { cycle, newFindings: cycle === 1 ? active : fresh });
      } catch (err) {
        if (controller.signal.aborted) break;
        handlers.onError?.(err instanceof Error ? err : new Error(String(err)), { cycle });
      }
      if (controller.signal.aborted) break;
      await sleep(interval);
    }
  };

  const done = loop();
  return {
    done,
    async stop() {
      controller.abort();
      if (timer) clearTimeout(timer);
      wake?.();
      await done;
    },
  };
}
