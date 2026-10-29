const express = require("express");
const { requireAuth } = require("../middleware/auth");

function createUsersRouter(store) {
  const router = express.Router();

  // Retrieve current user profile
  router.get("/me", requireAuth, (req, res) => {
    const user = store.getUser(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json(user);
  });

  // Update account email address
  router.put("/:id/email", requireAuth, (req, res) => {
    const email = req.body && req.body.email;
    if (typeof email !== "string" || !email.includes("@")) {
      return res.status(400).json({ error: "Valid email required" });
    }
    const updated = store.updateUserEmail(req.params.id, email);
    if (!updated) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json(updated);
  });

  return router;
}

module.exports = { createUsersRouter };
