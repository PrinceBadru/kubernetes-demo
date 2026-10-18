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

let effectivePassword =
  process.env.PG_PASSWORD ||
  process.env.POSTGRES_PASSWORD ||
  (process.env.NODE_ENV === 'production' ? undefined : 'CHANGE_ME_IN_PRODUCTION');

if (process.env.DATABASE_URL) {
  try {
    const parsedUrl = new URL(process.env.DATABASE_URL);
    if (parsedUrl.password) {
      effectivePassword = decodeURIComponent(parsedUrl.password);
    }
  } catch (err) {
    throw new Error(`Invalid DATABASE_URL configuration: ${err.message}`);
  }
}

validateDbPassword(effectivePassword);

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
      password: effectivePassword,
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
        query_timeout: 2500,
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

const DECIMAL_INT_REGEX = /^[1-9]\d*$/;

/**
 * Queries audit log records using strictly parameterized prepared statements.
 *
 * DevSecOps Principle (OWASP A03:2021 / CWE-89):
 * Prepared statements with positional placeholder variables ($1, $2) guarantee that
 * untrusted client inputs are treated purely as literal data values, making SQL injection
 * impossible regardless of payload content.
 *
 * @param {Object} options
 * @param {number|string} [options.id] - Optional record ID (strict positive integer)
 * @param {string} [options.search] - Optional action substring to search
 * @param {number|string} [options.limit=10] - Result limit (bounded between 1 and 50)
 * @returns {Promise<Array<Object>>}
 */
export const queryRecords = async ({ id, search, limit = 10 } = {}) => {
  let safeLimit = 10;
  if (limit !== undefined && limit !== null && limit !== '') {
    const strLimit = String(limit).trim();
    if (!DECIMAL_INT_REGEX.test(strLimit) || !Number.isSafeInteger(Number(strLimit))) {
      const err = new Error('Invalid limit: must be a positive integer in standard decimal format');
      err.status = 400;
      throw err;
    }
    safeLimit = Math.min(Math.max(Number(strLimit), 1), 50);
  }

  if (id !== undefined && id !== null && id !== '') {
    const strId = String(id).trim();
    if (!DECIMAL_INT_REGEX.test(strId) || !Number.isSafeInteger(Number(strId))) {
      const err = new Error(
        'Invalid record ID: must be a positive integer in standard decimal format',
      );
      err.status = 400;
      throw err;
    }
    const numericId = Number(strId);
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
    if (!fs.existsSync(initSqlPath)) {
      throw new Error(`Canonical schema file not found at ${initSqlPath}`);
    }
    const sqlContent = fs.readFileSync(initSqlPath, 'utf8');
    await pool.query(sqlContent);
    console.info('[DB] Schema and seed data initialized successfully from canonical init.sql');
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
