import sqlite3 from 'sqlite3';

// Centralized schema migrations for the local CipherNode SQLite store.
const SCHEMA_VERSION = 1;
const MIGRATIONS = [
  `
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS users (
      uid TEXT PRIMARY KEY,
      public_key TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen INTEGER
  );

  CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      status TEXT NOT NULL CHECK (status IN ('active', 'archived', 'blocked')),
      ephemeral_toggle INTEGER NOT NULL DEFAULT 0,
      ttl_setting INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      sender_id TEXT NOT NULL,
      payload_encrypted BLOB NOT NULL,
      file_blob_pointer TEXT,
      timestamp INTEGER NOT NULL,
      read_status INTEGER NOT NULL DEFAULT 0,
      expiry_timestamp INTEGER,
      FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
      FOREIGN KEY (sender_id) REFERENCES users(uid) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, timestamp);
  CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages(read_status, expiry_timestamp);
  `,
];

const OPEN_FLAGS = sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE | sqlite3.OPEN_FULLMUTEX;

// Promise-based helpers enforce parameter binding to avoid SQL injection.
const run = (db, sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) {
        reject(err);
        return;
      }
      resolve({ changes: this.changes, lastID: this.lastID });
    });
  });

const exec = (db, sql) =>
  new Promise((resolve, reject) => {
    db.exec(sql, (err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });

const get = (db, sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row);
    });
  });

const all = (db, sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows);
    });
  });

// SQLite is single-writer; this pool guards concurrency for desktop/Node contexts.
export class CipherNodeDatabasePool {
  constructor({ filename, poolSize = 4 }) {
    this.filename = filename;
    this.poolSize = poolSize;
    this.available = [];
    this.waitQueue = [];
  }

  // Opens pooled connections and applies migrations once.
  async initialize() {
    const connections = [];
    for (let i = 0; i < this.poolSize; i += 1) {
      connections.push(this.#openConnection());
    }
    this.available = await Promise.all(connections);
    await this.#migrate(this.available[0]);
    return this;
  }

  // Runs the provided callback with a pooled connection.
  async withConnection(fn) {
    const db = await this.#acquire();
    try {
      return await fn(new CipherNodeConnection(db));
    } finally {
      this.#release(db);
    }
  }

  // Opens a single SQLite connection with secure PRAGMA defaults.
  async #openConnection() {
    const db = await new Promise((resolve, reject) => {
      const connection = new sqlite3.Database(this.filename, OPEN_FLAGS, (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(connection);
      });
    });
    await run(db, 'PRAGMA foreign_keys = ON;');
    await run(db, 'PRAGMA journal_mode = WAL;');
    await run(db, 'PRAGMA synchronous = NORMAL;');
    await run(db, 'PRAGMA busy_timeout = 5000;');
    return db;
  }

  // Migrates the schema using transactional execution.
  async #migrate(db) {
    const row = await get(db, 'PRAGMA user_version;');
    const currentVersion = row?.user_version ?? 0;
    if (currentVersion >= SCHEMA_VERSION) {
      return;
    }
    await run(db, 'BEGIN IMMEDIATE;');
    try {
      for (let idx = currentVersion; idx < MIGRATIONS.length; idx += 1) {
        await exec(db, MIGRATIONS[idx]);
      }
      // SCHEMA_VERSION is a trusted constant; keep PRAGMA assignment deterministic.
      await run(db, `PRAGMA user_version = ${SCHEMA_VERSION};`);
      await run(db, 'COMMIT;');
    } catch (error) {
      await run(db, 'ROLLBACK;');
      throw error;
    }
  }

  async #acquire() {
    if (this.available.length) {
      return this.available.pop();
    }
    return new Promise((resolve) => {
      this.waitQueue.push(resolve);
    });
  }

  #release(db) {
    const waiter = this.waitQueue.shift();
    if (waiter) {
      waiter(db);
      return;
    }
    this.available.push(db);
  }
}

// Connection wrapper to standardize prepared statement usage.
export class CipherNodeConnection {
  constructor(db) {
    this.db = db;
  }

  run(sql, params) {
    return run(this.db, sql, params);
  }

  get(sql, params) {
    return get(this.db, sql, params);
  }

  all(sql, params) {
    return all(this.db, sql, params);
  }

  async prepared(sql, params, handler) {
    const statement = this.db.prepare(sql);
    return new Promise((resolve, reject) => {
      statement.bind(params, (bindErr) => {
        if (bindErr) {
          statement.finalize();
          reject(bindErr);
          return;
        }
        handler(statement, (handlerErr, result) => {
          statement.finalize();
          if (handlerErr) {
            reject(handlerErr);
            return;
          }
          resolve(result);
        });
      });
    });
  }
}
