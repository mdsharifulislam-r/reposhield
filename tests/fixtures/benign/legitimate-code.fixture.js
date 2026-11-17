// INERT TEST FIXTURE — Benign Dynamic Import
// This file represents LEGITIMATE use of dynamic imports.
// The scanner must NOT flag this as malicious.

// Legitimate: dynamic import with static string literal
async function loadPlugin(name) {
  // Static module name — safe
  if (name === 'fast') {
    const { fastProcess } = await import('./plugins/fast-processor.js');
    return fastProcess;
  }
  const { defaultProcess } = await import('./plugins/default-processor.js');
  return defaultProcess;
}

// Legitimate: Buffer.from for encoding, NOT decoded to exec
function encodeData(data) {
  return Buffer.from(data, 'utf-8').toString('base64');
}

// Legitimate: fetch for API calls (not followed by eval)
async function fetchUserData(userId) {
  const response = await fetch(`/api/users/${userId}`);
  return response.json(); // JSON parsing, not eval
}

// Legitimate: child_process in a build script context
const { execSync } = require('child_process');
function getGitHash() {
  return execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
}

module.exports = { loadPlugin, encodeData, fetchUserData, getGitHash };
