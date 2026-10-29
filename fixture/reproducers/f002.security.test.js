const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-002 IDOR: Bob cannot overwrite Alice email", async () => {
  const app = createApp();
  const bobToken = signToken({ id: "u-bob", username: "bob", role: "user" });
  const res = await request(app)
    .put("/api/users/u-alice/email")
    .set("Authorization", `Bearer ${bobToken}`)
    .send({ email: "hijacked@evil.test" });
  invariant(
    "IDOR-USER-EMAIL",
    res.status === 403 || res.status === 404,
    `Expected 403/404 when Bob updates u-alice email, got ${res.status}`
  );
});
