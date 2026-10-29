const crypto = require("crypto");

function getEnvSecret() {
  const secret = process.env.AUTH_TOKEN_SECRET;
  if (!secret) {
    throw new Error("AUTH_TOKEN_SECRET environment variable is required");
  }
  return secret;
}

function signToken(payload, explicitSecret) {
  const secret = explicitSecret || getEnvSecret();
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(encoded).digest("hex");
  return `${encoded}.${sig}`;
}

function verifyTokenWithSecret(token, secret) {
  if (!token || typeof token !== "string" || !token.includes(".")) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [encoded, providedSig] = parts;
  const expectedSig = crypto.createHmac("sha256", secret).update(encoded).digest("hex");
  const a = Buffer.from(providedSig, "utf8");
  const b = Buffer.from(expectedSig, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch (_err) {
    return null;
  }
}

function extractBearer(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  return header.slice("Bearer ".length).trim();
}

function requireAuth(req, res, next) {
  let secret;
  try {
    secret = getEnvSecret();
  } catch (_err) {
    return res.status(500).json({ error: "Auth secret not configured" });
  }
  const raw = extractBearer(req);
  const claims = verifyTokenWithSecret(raw, secret);
  if (!claims || !claims.id) {
    return res.status(401).json({ error: "Authentication required" });
  }
  req.user = claims;
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin role required" });
  }
  return next();
}

module.exports = {
  signToken,
  verifyTokenWithSecret,
  extractBearer,
  requireAuth,
  requireAdmin,
};
