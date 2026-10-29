const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-005 INJECTION: command injection marker is not executed", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/search/logs")
    .query({ keyword: "STARTUP && echo CMD_INJ_MARKER_771" })
    .set("Authorization", `Bearer ${aliceToken}`);
  const matches = (res.body && res.body.matches) || [];
  const executed = matches.some((line) => String(line).includes("CMD_INJ_MARKER_771"));
  invariant(
    "INJ-LOG-CMD",
    !executed,
    `Shell command injection executed; matches=${JSON.stringify(matches)}`
  );
});
