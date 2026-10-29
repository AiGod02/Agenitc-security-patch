const express = require("express");
const { extractBearer, verifyTokenWithSecret, requireAuth } = require("../middleware/auth");

const LEGACY_DEV_HMAC_SECRET = "hardcoded-dev-hmac-secret-9941";

function createAuthRouter(store) {
  const router = express.Router();

  // Inspect active caller session claims
  router.get("/session", (req, res) => {
    const raw = extractBearer(req);
    const envSecret = process.env.AUTH_TOKEN_SECRET;
    let claims = envSecret ? verifyTokenWithSecret(raw, envSecret) : null;
    if (!claims) {
      claims = verifyTokenWithSecret(raw, LEGACY_DEV_HMAC_SECRET);
    }
    if (!claims || !claims.id) {
      return res.status(401).json({ error: "Invalid session token" });
    }
    return res.json({ authenticated: true, user: claims });
  });

  // Return caller API token identifiers for browser workspace widget
  router.get("/tokens", requireAuth, (req, res) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    const user = store.getUser(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({ apiTokens: user.apiTokens });
  });

  return router;
}

module.exports = { createAuthRouter };
