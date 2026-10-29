const request = require("supertest");
const { createApp } = require("../src/app");
const { signToken } = require("../src/middleware/auth");

describe("Express fixture baseline functional suite", () => {
  const aliceToken = () => signToken({ id: "u-alice", username: "alice", role: "user" });
  const adminToken = () => signToken({ id: "u-admin", username: "admin", role: "admin" });

  test("GET /api/health returns ok", async () => {
    const app = createApp();
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });

  test("GET and POST /api/invoices manage caller invoices", async () => {
    const app = createApp();
    const listRes = await request(app)
      .get("/api/invoices")
      .set("Authorization", `Bearer ${aliceToken()}`);
    expect(listRes.status).toBe(200);
    expect(listRes.body.invoices).toHaveLength(1);
    expect(listRes.body.invoices[0].id).toBe("inv-1001");

    const createRes = await request(app)
      .post("/api/invoices")
      .set("Authorization", `Bearer ${aliceToken()}`)
      .send({ amountCents: 9900, confidentialNote: "Q4 addon" });
    expect(createRes.status).toBe(201);
    expect(createRes.body.ownerId).toBe("u-alice");
  });

  test("GET /api/users/me returns authenticated user profile", async () => {
    const app = createApp();
    const res = await request(app)
      .get("/api/users/me")
      .set("Authorization", `Bearer ${aliceToken()}`);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe("alice");
  });

  test("GET /api/files/list lists public files and downloads welcome.txt", async () => {
    const app = createApp();
    const listRes = await request(app)
      .get("/api/files/list")
      .set("Authorization", `Bearer ${aliceToken()}`);
    expect(listRes.status).toBe(200);
    expect(listRes.body.files).toContain("welcome.txt");

    const dlRes = await request(app)
      .get("/api/files/download")
      .query({ name: "welcome.txt" })
      .set("Authorization", `Bearer ${aliceToken()}`);
    expect(dlRes.status).toBe(200);
    expect(dlRes.body.content).toContain("Welcome to the internal customer portal");
  });

  test("GET /api/search/logs and /api/search/users work on normal inputs", async () => {
    const app = createApp();
    const logRes = await request(app)
      .get("/api/search/logs")
      .query({ keyword: "STARTUP" })
      .set("Authorization", `Bearer ${aliceToken()}`);
    expect(logRes.status).toBe(200);
    expect(logRes.body.matches[0]).toContain("STARTUP");

    const userRes = await request(app)
      .get("/api/search/users")
      .query({ department: "engineering" })
      .set("Authorization", `Bearer ${aliceToken()}`);
    expect(userRes.status).toBe(200);
    expect(userRes.body.users).toHaveLength(1);
    expect(userRes.body.users[0].username).toBe("alice");
  });

  test("GET /api/admin/stats enforces admin role", async () => {
    const app = createApp();
    const denied = await request(app)
      .get("/api/admin/stats")
      .set("Authorization", `Bearer ${aliceToken()}`);
    expect(denied.status).toBe(403);

    const allowed = await request(app)
      .get("/api/admin/stats")
      .set("Authorization", `Bearer ${adminToken()}`);
    expect(allowed.status).toBe(200);
    expect(allowed.body.totalUsers).toBe(3);
  });
});
