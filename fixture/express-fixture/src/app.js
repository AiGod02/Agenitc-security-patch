const express = require("express");
const { createStore } = require("./store");
const { createDirectoryDb } = require("./db");
const { createInvoicesRouter } = require("./routes/invoices");
const { createUsersRouter } = require("./routes/users");
const { createFilesRouter } = require("./routes/files");
const { createSearchRouter } = require("./routes/search");
const { createAdminRouter } = require("./routes/admin");
const { createAuthRouter } = require("./routes/auth");
const { createWebhooksRouter } = require("./routes/webhooks");
const { createExportsRouter } = require("./routes/exports");

function createApp() {
  const app = express();
  app.use(express.json());

  const store = createStore();
  let dbPromise = null;
  const getDb = () => {
    if (!dbPromise) {
      dbPromise = createDirectoryDb();
    }
    return dbPromise;
  };

  // Service health probe
  app.get("/api/health", (_req, res) => {
    return res.json({ status: "ok" });
  });

  app.use("/api/invoices", createInvoicesRouter(store));
  app.use("/api/users", createUsersRouter(store));
  app.use("/api/files", createFilesRouter());
  app.use("/api/search", createSearchRouter(getDb));
  app.use("/api/admin", createAdminRouter(store));
  app.use("/api/auth", createAuthRouter(store));
  app.use("/api/webhooks", createWebhooksRouter(store));
  app.use("/api/exports", createExportsRouter(store));

  return app;
}

const app = createApp();

module.exports = { createApp, app };
