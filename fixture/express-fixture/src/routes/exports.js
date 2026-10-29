const express = require("express");
const { requireAuth } = require("../middleware/auth");

function createExportsRouter(store) {
  const router = express.Router();

  // Return invoice summary for embedded analytics client
  router.get("/summary", requireAuth, (req, res) => {
    const requestOrigin = req.headers.origin || "*";
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    const invoices = store.listInvoicesForOwner(req.user.id);
    const totalCents = invoices.reduce((acc, item) => acc + item.amountCents, 0);
    return res.json({ ownerId: req.user.id, count: invoices.length, totalCents });
  });

  return router;
}

module.exports = { createExportsRouter };
