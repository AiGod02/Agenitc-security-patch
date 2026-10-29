const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-006 companion: normal department=engineering returns alice", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/search/users")
    .query({ department: "engineering" })
    .set("Authorization", `Bearer ${aliceToken}`);
  expect(res.status).toBe(200);
  expect(res.body.users).toHaveLength(1);
  expect(res.body.users[0].username).toBe("alice");
});
