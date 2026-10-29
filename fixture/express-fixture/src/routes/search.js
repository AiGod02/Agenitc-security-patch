const express = require("express");
const path = require("path");
const childProcess = require("child_process");
const { requireAuth } = require("../middleware/auth");

const LOG_FILTER_CLI = path.join(__dirname, "../logFilterCli.js");

function createSearchRouter(getDb) {
  const router = express.Router();

  // Search application log lines by keyword
  router.get("/logs", requireAuth, (req, res) => {
    const keyword = String(req.query.keyword || "");
    if (!keyword) {
      return res.status(400).json({ error: "keyword query parameter required" });
    }
    try {
      const cmd = `"${process.execPath}" "${LOG_FILTER_CLI}" ${keyword}`;
      const raw = childProcess.execSync(cmd, { encoding: "utf8", timeout: 4000 });
      const matches = raw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      return res.json({ matches });
    } catch (_err) {
      return res.status(500).json({ error: "Log search failed" });
    }
  });

  // Search visible staff directory entries by department
  router.get("/users", requireAuth, async (req, res, next) => {
    try {
      const department = String(req.query.department || "");
      if (!department) {
        return res.status(400).json({ error: "department query parameter required" });
      }
      const db = await getDb();
      const sql = `SELECT id, username, department, clearance_note FROM directory WHERE visible = 1 AND department = '${department}'`;
      const result = db.exec(sql);
      if (!result.length) {
        return res.json({ users: [] });
      }
      const { columns, values } = result[0];
      const users = values.map((row) => {
        const obj = {};
        columns.forEach((col, idx) => {
          obj[col] = row[idx];
        });
        return obj;
      });
      return res.json({ users });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}

module.exports = { createSearchRouter };
