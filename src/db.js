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

import pg from 'pg';
import { dbPoolActiveConnections, dbQueryDurationSeconds } from './metrics.js';

const { Pool } = pg;

// Construct pool options from individual env variables or a full DATABASE_URL
const poolConfig = process.env.DATABASE_URL
  ? {
      connectionString: process.env.DATABASE_URL,
      max: parseInt(process.env.PG_POOL_MAX || '10', 10),
      idleTimeoutMillis: parseInt(process.env.PG_IDLE_TIMEOUT_MS || '30000', 10),
      connectionTimeoutMillis: parseInt(process.env.PG_CONN_TIMEOUT_MS || '5000', 10),
    }
  : {
      host: process.env.PG_HOST || 'localhost',
      port: parseInt(process.env.PG_PORT || '5432', 10),
      user: process.env.PG_USER || 'app',
      password: process.env.PG_PASSWORD || 'CHANGE_ME_IN_PRODUCTION',
      database: process.env.PG_DATABASE || 'auditor',
      max: parseInt(process.env.PG_POOL_MAX || '10', 10),
      idleTimeoutMillis: parseInt(process.env.PG_IDLE_TIMEOUT_MS || '30000', 10),
      connectionTimeoutMillis: parseInt(process.env.PG_CONN_TIMEOUT_MS || '5000', 10),
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
    await Promise.race([pool.query('SELECT 1'), timeoutPromise]);

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

/**
 * Automatically creates the audit_logs table and seeds deterministic demo data.
 */
export const initSchema = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        action VARCHAR(64) NOT NULL,
        actor VARCHAR(64) NOT NULL,
        details TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      INSERT INTO audit_logs (action, actor, details)
      SELECT 'USER_LOGIN', 'admin@demo.local', 'Successful authentication from trusted internal CIDR'
      WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'USER_LOGIN');
      INSERT INTO audit_logs (action, actor, details)
      SELECT 'KEY_ROTATION', 'system', 'Automated service account token rotation completed'
      WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'KEY_ROTATION');
      INSERT INTO audit_logs (action, actor, details)
      SELECT 'DEPLOYMENT', 'ci-runner', 'Version 1.0.0 deployed to devsecops-demo namespace'
      WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'DEPLOYMENT');
      INSERT INTO audit_logs (action, actor, details)
      SELECT 'POLICY_AUDIT', 'security-scanner', 'Zero-trust network policies and Pod Security Admission validated'
      WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'POLICY_AUDIT');
    `);
    console.info('[DB] Schema and seed data initialized successfully');
  } catch (err) {
    console.warn('[DB] Schema initialization deferred or unavailable:', err.message);
  }
};

export default {
  pool,
  checkPostgres,
  queryRecords,
  initSchema,
};
