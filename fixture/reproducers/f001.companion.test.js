const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-001 companion: Alice can read her own invoice inv-1001", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/invoices/inv-1001")
    .set("Authorization", `Bearer ${aliceToken}`);
  expect(res.status).toBe(200);
  expect(res.body.id).toBe("inv-1001");
  expect(res.body.ownerId).toBe("u-alice");
});
