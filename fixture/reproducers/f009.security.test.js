const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-009 HARDCODED_SECRET: forged token signed with hardcoded fallback secret is rejected", async () => {
  process.env.AUTH_TOKEN_SECRET = "runtime-env-secret-only";
  const app = createApp();
  const forged = signToken(
    { id: "u-admin", username: "admin", role: "admin" },
    "hardcoded-dev-hmac-secret-9941"
  );
  const res = await request(app)
    .get("/api/auth/session")
    .set("Authorization", `Bearer ${forged}`);
  invariant(
    "SECRET-SESSION-HMAC",
    res.status === 401 || res.status === 403,
    `Hardcoded fallback secret token accepted with status=${res.status}`
  );
});
