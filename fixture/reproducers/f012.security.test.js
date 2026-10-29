const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-012 PERMISSIVE_CORS: untrusted Origin is not echoed with credentials on /api/exports/summary", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const evilOrigin = "https://malicious.example";
  const res = await request(app)
    .get("/api/exports/summary")
    .set("Origin", evilOrigin)
    .set("Authorization", `Bearer ${aliceToken}`);
  const acao = res.headers["access-control-allow-origin"];
  const acac = res.headers["access-control-allow-credentials"];
  const vulnerable = (acao === evilOrigin || acao === "*") && acac === "true";
  invariant(
    "CORS-EXPORT-SUMMARY",
    !vulnerable,
    `Reflected untrusted origin=${acao} with credentials=${acac}`
  );
});
