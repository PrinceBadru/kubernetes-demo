/**
 * @fileoverview PostgreSQL Database Connection Pool & Health Check Module
 *
 * DevSecOps Principles:
 * 1. Connection Pooling & Resource Exhaustion Defense:
 *    Maintains a controlled pool (`pg.Pool`) of connections with explicit max limits,
 *    idle timeouts, and connection timeouts. Prevents Denial of Service (DoS) from
 *    connection starvation and unconstrained socket creation in Kubernetes pods.
 * 2. Least Privilege Configuration:
 *    Configured for the restricted application database user (`app`) targeting the
 *    dedicated database (`auditor`), avoiding administrative superuser credentials.
 * 3. Resilient Health Probing:
 *    Implements `checkPostgres()` with a strict 3000ms timeout to ensure Kubernetes
 *    readiness and deep health checks fail gracefully without hanging indefinitely.
 * 4. Observability & Connection Auditing:
 *    Logs pool events (connect, acquire, release, remove, error) without leaking
 *    credentials, and exposes active connection count directly to Prometheus.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { dbPoolActiveConnections, dbQueryDurationSeconds } from './metrics.js';

const { Pool } = pg;

const parsePositiveInt = (val, defaultVal, min = 1, max = 65535) => {
  if (val === undefined || val === null || val === '') return defaultVal;
  const num = Number(val);
  if (!Number.isInteger(num) || num < min || num > max) {
    throw new Error(
      `Invalid numeric configuration: "${val}". Must be an integer between ${min} and ${max}.`,
    );
  }
  return num;
};

const INSECURE_DEFAULT_PASSWORDS = [
  'change_me_in_production',
  'change_this_in_production',
  'devsecops-demo',
  'replace_with_secure_postgres_password',
];

const validateDbPassword = (password) => {
  if (process.env.NODE_ENV === 'production') {
    if (!password || INSECURE_DEFAULT_PASSWORDS.includes(String(password).toLowerCase())) {
      throw new Error(
        'FATAL: Insecure or default database password detected in production environment. A secure, non-default credential must be supplied.',
      );
    }
  }
};

const rawPassword =
  process.env.PG_PASSWORD ||
  process.env.POSTGRES_PASSWORD ||
  (process.env.NODE_ENV === 'production' ? undefined : 'CHANGE_ME_IN_PRODUCTION');

if (!process.env.DATABASE_URL) {
  validateDbPassword(rawPassword);
}

// Construct pool options from individual env variables or a full DATABASE_URL
// Supports both PG_* and POSTGRES_* variable conventions (DevSecOps interoperability)
const poolConfig = process.env.DATABASE_URL
  ? {
      connectionString: process.env.DATABASE_URL,
      max: parsePositiveInt(process.env.PG_POOL_MAX, 10, 1, 100),
      idleTimeoutMillis: parsePositiveInt(process.env.PG_IDLE_TIMEOUT_MS, 30000, 1000, 300000),
      connectionTimeoutMillis: parsePositiveInt(process.env.PG_CONN_TIMEOUT_MS, 5000, 500, 60000),
    }
  : {
      host: process.env.PG_HOST || process.env.POSTGRES_HOST || 'localhost',
      port: parsePositiveInt(process.env.PG_PORT || process.env.POSTGRES_PORT, 5432, 1, 65535),
      user: process.env.PG_USER || process.env.POSTGRES_USER || 'app',
      password: rawPassword,
      database: process.env.PG_DATABASE || process.env.POSTGRES_DB || 'auditor',
      max: parsePositiveInt(process.env.PG_POOL_MAX, 10, 1, 100),
      idleTimeoutMillis: parsePositiveInt(process.env.PG_IDLE_TIMEOUT_MS, 30000, 1000, 300000),
      connectionTimeoutMillis: parsePositiveInt(process.env.PG_CONN_TIMEOUT_MS, 5000, 500, 60000),
    };

/**
 * PostgreSQL connection pool instance.
 */
export const pool = new Pool(poolConfig);

/**
 * Updates the Prometheus active connection gauge based on pool state.
 */
const updatePoolMetrics = () => {
  const activeCount = Math.max(0, pool.totalCount - pool.idleCount);
  dbPoolActiveConnections.set(activeCount);
};

// Event handlers for auditing connection lifecycle and updating metrics
pool.on('connect', () => {
  console.info('[DB] New client connection established in PostgreSQL pool');
  updatePoolMetrics();
});

pool.on('acquire', () => {
  updatePoolMetrics();
});

pool.on('release', () => {
  updatePoolMetrics();
});

pool.on('remove', () => {
  console.info('[DB] Client removed from PostgreSQL pool');
  updatePoolMetrics();
});

pool.on('error', (err) => {
  // Idle client error handling to prevent uncaught process termination
  console.error('[DB] Unexpected error on idle PostgreSQL client:', err.message);
  updatePoolMetrics();
});

/**
 * Executes a PostgreSQL health probe query (`SELECT 1`) with a strict 3-second timeout.
 *
 * DevSecOps Rationale:
 * Guarantees that database latency spikes, locks, or network partitions do not block
 * API threads or cause Kubernetes readiness checks to cascade into full outages.
 *
 * @returns {Promise<{ ok: boolean, latencyMs: number, error?: string }>}
 */
export const checkPostgres = async () => {
  const start = performance.now();
  let timerId;

  const timeoutPromise = new Promise((_, reject) => {
    timerId = setTimeout(() => {
      reject(new Error('PostgreSQL health check probe timed out after 3000ms'));
    }, 3000);
  });

  try {
    await Promise.race([
      pool.query({
        text: 'SELECT 1',
        statement_timeout: 2500,
      }),
      timeoutPromise,
    ]);

    const latencyMs = Math.round(performance.now() - start);
    dbQueryDurationSeconds.observe(latencyMs / 1000);
    updatePoolMetrics();

    return { ok: true, latencyMs };
  } catch (error) {
    const latencyMs = Math.round(performance.now() - start);
    console.error('[DB] PostgreSQL health check failed:', error.message);
    updatePoolMetrics();

    return { ok: false, latencyMs, error: error.message };
  } finally {
    clearTimeout(timerId);
  }
};

/**
 * Queries audit log records using strictly parameterized prepared statements.
 *
 * DevSecOps Principle (OWASP A03:2021 / CWE-89):
 * Prepared statements with positional placeholder variables ($1, $2) guarantee that
 * untrusted client inputs are treated purely as literal data values, making SQL injection
 * impossible regardless of payload content.
 *
 * @param {Object} options
 * @param {number} [options.id] - Optional record ID
 * @param {string} [options.search] - Optional action substring to search
 * @param {number} [options.limit=10] - Result limit (bounded between 1 and 50)
 * @returns {Promise<Array<Object>>}
 */
export const queryRecords = async ({ id, search, limit = 10 } = {}) => {
  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 10, 1), 50);

  if (id !== undefined && id !== null && id !== '') {
    const numericId = Number(id);
    if (!Number.isInteger(numericId) || numericId <= 0) {
      const err = new Error('Invalid record ID: must be a positive integer');
      err.status = 400;
      throw err;
    }
    const result = await pool.query(
      'SELECT id, action, actor, details, created_at FROM audit_logs WHERE id = $1 LIMIT 1',
      [numericId],
    );
    return result.rows;
  }

  if (search) {
    const trimmedSearch = String(search).slice(0, 100);
    const result = await pool.query(
      'SELECT id, action, actor, details, created_at FROM audit_logs WHERE action ILIKE $1 OR details ILIKE $1 ORDER BY id ASC LIMIT $2',
      [`%${trimmedSearch}%`, safeLimit],
    );
    return result.rows;
  }

  const result = await pool.query(
    'SELECT id, action, actor, details, created_at FROM audit_logs ORDER BY id ASC LIMIT $1',
    [safeLimit],
  );
  return result.rows;
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const initSqlPath = path.join(__dirname, 'db', 'init.sql');

/**
 * Automatically creates the audit_logs table and seeds deterministic demo data.
 * Reads canonical SQL schema from src/db/init.sql (Single Source of Truth).
 */
export const initSchema = async () => {
  try {
    let sqlContent;
    if (fs.existsSync(initSqlPath)) {
      sqlContent = fs.readFileSync(initSqlPath, 'utf8');
    } else {
      sqlContent = `
        CREATE TABLE IF NOT EXISTS audit_logs (
          id SERIAL PRIMARY KEY,
          action VARCHAR(64) NOT NULL,
          actor VARCHAR(64) NOT NULL,
          details TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
        INSERT INTO audit_logs (id, action, actor, details)
        VALUES 
          (1, 'USER_LOGIN', 'admin@demo.local', 'Successful authentication from trusted internal CIDR'),
          (2, 'KEY_ROTATION', 'system', 'Automated service account token rotation completed'),
          (3, 'DEPLOYMENT', 'ci-runner', 'Version 1.0.0 deployed to devsecops-demo namespace'),
          (4, 'POLICY_AUDIT', 'security-scanner', 'Zero-trust network policies and Pod Security Admission validated')
        ON CONFLICT (id) DO NOTHING;
        SELECT setval(pg_get_serial_sequence('audit_logs', 'id'), COALESCE((SELECT MAX(id) FROM audit_logs), 1));
      `;
    }
    await pool.query(sqlContent);
    console.info('[DB] Schema and seed data initialized successfully');
    return true;
  } catch (err) {
    console.warn('[DB] Schema initialization deferred or unavailable:', err.message);
    return false;
  }
};

export default {
  pool,
  checkPostgres,
  queryRecords,
  initSchema,
};
