const request = require("supertest");
const { createApp } = require("../../src/app");
const { signToken } = require("../../src/middleware/auth");
const { invariant } = require("../helpers/invariant");

test("F-001 IDOR: Bob cannot read Alice invoice inv-1001", async () => {
  const app = createApp();
  const bobToken = signToken({ id: "u-bob", username: "bob", role: "user" });
  const res = await request(app)
    .get("/api/invoices/inv-1001")
    .set("Authorization", `Bearer ${bobToken}`);
  invariant(
    "IDOR-INVOICE-READ",
    res.status === 403 || res.status === 404,
    `Expected 403/404 when Bob requests Alice invoice, got ${res.status} with ownerId=${res.body && res.body.ownerId}`
  );
});
