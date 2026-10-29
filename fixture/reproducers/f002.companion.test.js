const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-002 companion: Alice can update her own email", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .put("/api/users/u-alice/email")
    .set("Authorization", `Bearer ${aliceToken}`)
    .send({ email: "alice.updated@example.com" });
  expect(res.status).toBe(200);
  expect(res.body.email).toBe("alice.updated@example.com");
});
