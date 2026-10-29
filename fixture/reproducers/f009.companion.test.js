const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-009 companion: session accepts token signed with AUTH_TOKEN_SECRET env", async () => {
  process.env.AUTH_TOKEN_SECRET = "runtime-env-secret-only";
  const app = createApp();
  const valid = signToken(
    { id: "u-alice", username: "alice", role: "user" },
    process.env.AUTH_TOKEN_SECRET
  );
  const res = await request(app)
    .get("/api/auth/session")
    .set("Authorization", `Bearer ${valid}`);
  expect(res.status).toBe(200);
  expect(res.body.authenticated).toBe(true);
});
