const express = require("express");
const fs = require("fs");
const path = require("path");
const { requireAuth } = require("../middleware/auth");

const STORAGE_ROOT = path.resolve(__dirname, "../../storage");
const PUBLIC_DIR = path.join(STORAGE_ROOT, "public");
const REPORTS_DIR = path.join(STORAGE_ROOT, "reports");

function createFilesRouter() {
  const router = express.Router();

  // List available public portal documents
  router.get("/list", requireAuth, (_req, res) => {
    const entries = fs.readdirSync(PUBLIC_DIR).filter((name) => !name.startsWith("."));
    return res.json({ files: entries });
  });

  // Download a document by filename from public storage
  router.get("/download", requireAuth, (req, res) => {
    const requestedName = String(req.query.name || "");
    if (!requestedName) {
      return res.status(400).json({ error: "name query parameter required" });
    }
    const targetPath = path.join(PUBLIC_DIR, requestedName);
    if (!fs.existsSync(targetPath) || !fs.statSync(targetPath).isFile()) {
      return res.status(404).json({ error: "File not found" });
    }
    const content = fs.readFileSync(targetPath, "utf8");
    return res.status(200).json({ name: requestedName, content });
  });

  // Read quarterly report text from reports storage
  router.get("/report", requireAuth, (req, res) => {
    const rawFile = String(req.query.file || "");
    if (!rawFile) {
      return res.status(400).json({ error: "file query parameter required" });
    }
    const sanitized = rawFile.replace(/^\.\//, "");
    const reportPath = path.join(REPORTS_DIR, sanitized);
    if (!fs.existsSync(reportPath) || !fs.statSync(reportPath).isFile()) {
      return res.status(404).json({ error: "Report not found" });
    }
    const reportText = fs.readFileSync(reportPath, "utf8");
    return res.status(200).json({ file: rawFile, content: reportText });
  });

  return router;
}

module.exports = { createFilesRouter, PUBLIC_DIR, REPORTS_DIR };
