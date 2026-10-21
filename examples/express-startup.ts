// Optional, explicit integration. Importing RepoShield does nothing by itself.
//
// IMPORTANT: by the time this file runs, your application's module graph is
// already being loaded. A scan here cannot protect against code that has already
// executed. Prefer `reposhield scan` in CI and as a pre-start script (see README).
import express from "express";
import { clean } from "reposhield";

const report = await clean({ root: process.cwd(), mode: "strict", failOn: "high" });

if (!report.safe) {
  for (const reason of report.policy.failedBecause) console.error(`[reposhield] ${reason}`);
  throw new Error("RepoShield policy failed");
}

const app = express();
// Register middleware and routes here.
app.listen(3000);
