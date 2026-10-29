const request = require("supertest");
const { createApp } = require("../../src/app");
const { invariant } = require("../helpers/invariant");

test("F-008 MISSING_AUTH: unauthenticated user deactivation is rejected", async () => {
  const app = createApp();
  const res = await request(app).post("/api/admin/users/u-alice/deactivate");
  invariant(
    "AUTH-ADMIN-DEACTIVATE",
    res.status === 401 || res.status === 403,
    `Expected 401/403 on unauthenticated deactivate, got ${res.status}`
  );
});
