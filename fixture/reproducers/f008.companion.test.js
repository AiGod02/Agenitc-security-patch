const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-008 companion: authenticated admin can deactivate a user", async () => {
  const app = createApp();
  const adminToken = signToken({ id: "u-admin", username: "admin", role: "admin" });
  const res = await request(app)
    .post("/api/admin/users/u-bob/deactivate")
    .set("Authorization", `Bearer ${adminToken}`);
  expect(res.status).toBe(200);
  expect(res.body.deactivated).toBe(true);
});
