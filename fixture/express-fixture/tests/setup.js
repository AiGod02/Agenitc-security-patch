if (!process.env.AUTH_TOKEN_SECRET) {
  process.env.AUTH_TOKEN_SECRET = "env-injected-test-signing-secret";
}
if (!process.env.WEBHOOK_API_KEY) {
  process.env.WEBHOOK_API_KEY = "env-injected-test-webhook-secret";
}
if (!process.env.ALLOWED_ORIGIN) {
  process.env.ALLOWED_ORIGIN = "https://app.internal.example";
}
