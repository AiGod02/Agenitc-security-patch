const request = require("supertest");
const { createApp } = require("../../src/app");
const { invariant } = require("../helpers/invariant");

test("F-010 HARDCODED_SECRET: hardcoded webhook key literal is rejected", async () => {
  process.env.WEBHOOK_API_KEY = "runtime-webhook-env-key";
  const app = createApp();
  const res = await request(app)
    .post("/api/webhooks/payment")
    .set("x-webhook-key", "whsec_live_hardcoded_88231")
    .send({ invoiceId: "inv-1001" });
  invariant(
    "SECRET-WEBHOOK-KEY",
    res.status === 401 || res.status === 403,
    `Hardcoded webhook key accepted with status=${res.status}`
  );
});
