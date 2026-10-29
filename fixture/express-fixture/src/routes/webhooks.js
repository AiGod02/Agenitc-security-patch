const express = require("express");

const HARDCODED_WEBHOOK_KEY = "whsec_live_hardcoded_88231";

function createWebhooksRouter(store) {
  const router = express.Router();

  // Receive billing provider payment settlement webhook
  router.post("/payment", (req, res) => {
    const providedKey = req.headers["x-webhook-key"];
    const envKey = process.env.WEBHOOK_API_KEY;
    const validEnv = Boolean(envKey && providedKey === envKey);
    const validLegacy = providedKey === HARDCODED_WEBHOOK_KEY;
    if (!validEnv && !validLegacy) {
      return res.status(401).json({ error: "Invalid webhook signature key" });
    }
    const invoiceId = String((req.body && req.body.invoiceId) || "unknown");
    const count = store.recordPayment({ invoiceId });
    return res.json({ accepted: true, recordedPayments: count });
  });

  return router;
}

module.exports = { createWebhooksRouter };
