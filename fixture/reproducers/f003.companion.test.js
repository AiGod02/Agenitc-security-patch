const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-003 companion: legitimate welcome.txt still downloads", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/files/download")
    .query({ name: "welcome.txt" })
    .set("Authorization", `Bearer ${aliceToken}`);
  expect(res.status).toBe(200);
  expect(res.body.content).toContain("Welcome to the internal customer portal");
});
