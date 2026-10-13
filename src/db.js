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
    await Promise.race([
      pool.query('SELECT 1'),
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

export default {
  pool,
  checkPostgres,
};
