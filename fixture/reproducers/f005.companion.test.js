const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");

test("F-005 companion: normal keyword STARTUP returns log match", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/search/logs")
    .query({ keyword: "STARTUP" })
    .set("Authorization", `Bearer ${aliceToken}`);
  expect(res.status).toBe(200);
  expect(res.body.matches.some((line) => line.includes("STARTUP"))).toBe(true);
});
