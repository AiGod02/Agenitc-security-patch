const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-003 PATH_TRAVERSAL: download rejects ../ traversal outside public dir", async () => {
  const app = createApp();
  const aliceToken = signToken({ id: "u-alice", username: "alice", role: "user" });
  const res = await request(app)
    .get("/api/files/download")
    .query({ name: "../private_keys/master_seed.txt" })
    .set("Authorization", `Bearer ${aliceToken}`);
  const leaked = res.body && String(res.body.content || "").includes("MASTER_SEED_DO_NOT_EXPOSE");
  invariant(
    "PATH-FILE-DOWNLOAD",
    (res.status === 400 || res.status === 403 || res.status === 404) && !leaked,
    `Expected traversal to be blocked, got status=${res.status} leaked=${leaked}`
  );
});
