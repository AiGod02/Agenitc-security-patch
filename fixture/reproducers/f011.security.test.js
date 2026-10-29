const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-011 PERMISSIVE_CORS: untrusted Origin is not echoed with credentials on /api/auth/tokens", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const evilOrigin = "https://evil.attacker.example";
  const res = await request(app)
    .get("/api/auth/tokens")
    .set("Origin", evilOrigin)
    .set("Authorization", `Bearer ${aliceToken}`);
  const acao = res.headers["access-control-allow-origin"];
  const acac = res.headers["access-control-allow-credentials"];
  const vulnerable = acao === evilOrigin && acac === "true";
  invariant(
    "CORS-AUTH-TOKENS",
    !vulnerable,
    `Reflected untrusted origin=${acao} with credentials=${acac}`
  );
});
