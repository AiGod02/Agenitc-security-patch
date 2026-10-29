const { createApp } = require("./app");

const port = Number(process.env.PORT || 0);
const app = createApp();
const server = app.listen(port, "127.0.0.1", () => {
  const addr = server.address();
  console.log(`Express fixture listening on http://127.0.0.1:${addr.port}`);
});

module.exports = { server };
