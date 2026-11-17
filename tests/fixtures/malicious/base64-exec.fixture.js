// INERT TEST FIXTURE — Base64 Decode to Execution
// This file is a test fixture for RepoShield scanner validation.
// It must NEVER be executed. It is analyzed statically only.

const encoded = Buffer.from('Y29uc29sZS5sb2coJ21hbGljaW91cycp', 'base64').toString('utf-8');
eval(encoded);

// Also atob pattern
const encoded2 = atob('aW50ZXJlc3Rpbmc=');
const fn = new Function(encoded2);
fn();
