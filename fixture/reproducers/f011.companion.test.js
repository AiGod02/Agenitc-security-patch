const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-011 companion: allowed origin https://app.internal.example receives tokens", async () => {
  process.env.ALLOWED_ORIGIN = "https://app.internal.example";
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/auth/tokens")
    .set("Origin", "https://app.internal.example")
    .set("Authorization", `Bearer ${aliceToken}`);
  expect(res.status).toBe(200);
  expect(res.headers["access-control-allow-origin"]).toBe("https://app.internal.example");
  expect(res.body.apiTokens).toContain("tok_meta_alice_01");
});
