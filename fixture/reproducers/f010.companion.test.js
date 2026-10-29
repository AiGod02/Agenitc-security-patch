const request = require("supertest");
const { createApp } = require("../../src/app");

test("F-010 companion: webhook accepts configured WEBHOOK_API_KEY from env", async () => {
  process.env.WEBHOOK_API_KEY = "runtime-webhook-env-key";
  const app = createApp();
  const res = await request(app)
    .post("/api/webhooks/payment")
    .set("x-webhook-key", "runtime-webhook-env-key")
    .send({ invoiceId: "inv-1001" });
  expect(res.status).toBe(200);
  expect(res.body.accepted).toBe(true);
});
