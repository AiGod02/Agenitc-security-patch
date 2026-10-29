const initSqlJs = require("sql.js");

let sqlModulePromise = null;

async function createDirectoryDb() {
  if (!sqlModulePromise) {
    sqlModulePromise = initSqlJs();
  }
  const SQL = await sqlModulePromise;
  const db = new SQL.Database();
  db.run(`
    CREATE TABLE directory (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      department TEXT NOT NULL,
      clearance_note TEXT NOT NULL,
      visible INTEGER NOT NULL
    );
  `);
  db.run(`
    INSERT INTO directory (id, username, department, clearance_note, visible) VALUES
      ('u-alice', 'alice', 'engineering', 'public-staff', 1),
      ('u-bob', 'bob', 'sales', 'public-staff', 1),
      ('u-exec-0', 'ceo_classified', 'executive', 'BOARD_MERGER_SECRET_2026', 0);
  `);
  return db;
}

module.exports = { createDirectoryDb };
