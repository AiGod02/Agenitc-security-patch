const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-007 companion: authenticated admin can read /api/admin/audit-log", async () => {
  const app = createApp();
  const adminToken = signToken({ id: "u-admin", username: "admin", role: "admin" });
  const res = await request(app)
    .get("/api/admin/audit-log")
    .set("Authorization", `Bearer ${adminToken}`);
  expect(res.status).toBe(200);
  expect(res.body.entries.length).toBeGreaterThanOrEqual(2);
});
