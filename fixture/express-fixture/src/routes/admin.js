const express = require("express");
const { requireAuth, requireAdmin } = require("../middleware/auth");

function createAdminRouter(store) {
  const router = express.Router();

  // Retrieve aggregate service counters
  router.get("/stats", requireAuth, requireAdmin, (_req, res) => {
    return res.json(store.getStats());
  });

  // Retrieve recent administrative audit trail entries
  router.get("/audit-log", (_req, res) => {
    return res.json({ entries: store.getAuditLog() });
  });

  // Mark an existing user account as inactive
  router.post("/users/:id/deactivate", (req, res) => {
    const updated = store.deactivateUser(req.params.id);
    if (!updated) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({ deactivated: true, user: updated });
  });

  return router;
}

module.exports = { createAdminRouter };
