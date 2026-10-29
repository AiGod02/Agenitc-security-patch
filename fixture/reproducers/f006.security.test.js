const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-006 INJECTION: SQL injection does not leak hidden directory rows", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/search/users")
    .query({ department: "engineering' OR '1'='1" })
    .set("Authorization", `Bearer ${aliceToken}`);
  const users = (res.body && res.body.users) || [];
  const leakedHidden = users.some(
    (u) => u.username === "ceo_classified" || String(u.clearance_note || "").includes("BOARD_MERGER_SECRET_2026")
  );
  invariant(
    "INJ-USER-SQL",
    !leakedHidden && users.length === 0,
    `SQL injection leaked rows: ${JSON.stringify(users)}`
  );
});
