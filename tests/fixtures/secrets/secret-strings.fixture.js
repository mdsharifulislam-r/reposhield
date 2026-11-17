// TEST FIXTURE — Secret-like Strings
// Contains realistic secret patterns for testing the secret detector.

// AWS Key pattern (test only)
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// GitHub token pattern (test only)
const GH_TOKEN = 'ghp_1234567890abcdef1234567890abcdef1234';

// npm token pattern (test only)
const NPM_TOKEN = 'npm_abcdefghijklmnopqrstuvwxyz1234567890';

// JWT example (test only)
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

module.exports = { AWS_ACCESS_KEY_ID, GH_TOKEN, NPM_TOKEN, JWT };
