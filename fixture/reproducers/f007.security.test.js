const request = require("supertest");
const { createApp } = require("../../src/app");
const { invariant } = require("../helpers/invariant");

test("F-007 MISSING_AUTH: unauthenticated request to /api/admin/audit-log is rejected", async () => {
  const app = createApp();
  const res = await request(app).get("/api/admin/audit-log");
  invariant(
    "AUTH-ADMIN-AUDIT",
    res.status === 401 || res.status === 403,
    `Expected 401/403 on unauthenticated /api/admin/audit-log, got ${res.status}`
  );
});
