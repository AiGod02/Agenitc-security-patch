function createStore() {
  const users = new Map([
    [
      "u-alice",
      {
        id: "u-alice",
        username: "alice",
        email: "alice@example.com",
        role: "user",
        active: true,
        apiTokens: ["tok_meta_alice_01"],
      },
    ],
    [
      "u-bob",
      {
        id: "u-bob",
        username: "bob",
        email: "bob@example.com",
        role: "user",
        active: true,
        apiTokens: ["tok_meta_bob_01"],
      },
    ],
    [
      "u-admin",
      {
        id: "u-admin",
        username: "admin",
        email: "admin@example.com",
        role: "admin",
        active: true,
        apiTokens: ["tok_meta_admin_01"],
      },
    ],
  ]);

  const invoices = new Map([
    [
      "inv-1001",
      {
        id: "inv-1001",
        ownerId: "u-alice",
        amountCents: 45000,
        currency: "USD",
        confidentialNote: "Alice private enterprise contract #A-99",
      },
    ],
    [
      "inv-2001",
      {
        id: "inv-2001",
        ownerId: "u-bob",
        amountCents: 12000,
        currency: "USD",
        confidentialNote: "Bob standard subscription #B-12",
      },
    ],
  ]);

  const auditLog = [
    { id: "aud-1", actor: "u-admin", action: "ROTATE_KEYS", target: "kms-prod" },
    { id: "aud-2", actor: "u-alice", action: "EXPORT_INVOICE", target: "inv-1001" },
  ];

  const payments = [];

  return {
    getUser(id) {
      const u = users.get(id);
      return u ? { ...u, apiTokens: [...u.apiTokens] } : null;
    },
    updateUserEmail(id, email) {
      const u = users.get(id);
      if (!u) return null;
      u.email = email;
      return { ...u, apiTokens: [...u.apiTokens] };
    },
    deactivateUser(id) {
      const u = users.get(id);
      if (!u) return null;
      u.active = false;
      return { ...u, apiTokens: [...u.apiTokens] };
    },
    listInvoicesForOwner(ownerId) {
      const out = [];
      for (const inv of invoices.values()) {
        if (inv.ownerId === ownerId) {
          out.push({ ...inv });
        }
      }
      return out;
    },
    getInvoice(id) {
      const inv = invoices.get(id);
      return inv ? { ...inv } : null;
    },
    createInvoice(ownerId, amountCents, confidentialNote) {
      const id = `inv-${3000 + invoices.size + 1}`;
      const record = {
        id,
        ownerId,
        amountCents,
        currency: "USD",
        confidentialNote: confidentialNote || "",
      };
      invoices.set(id, record);
      return { ...record };
    },
    getAuditLog() {
      return auditLog.map((entry) => ({ ...entry }));
    },
    getStats() {
      return {
        totalUsers: users.size,
        totalInvoices: invoices.size,
        recordedPayments: payments.length,
      };
    },
    recordPayment(event) {
      payments.push(event);
      return payments.length;
    },
  };
}

module.exports = { createStore };
