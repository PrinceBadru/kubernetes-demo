/**
 * @fileoverview Main Application Entrypoint for devsecops-demo-api
 *
 * DevSecOps Principles:
 * 1. Secure Defaults & Defense in Depth:
 *    - Strips `X-Powered-By` header to prevent technology fingerprinting.
 *    - Enforces OWASP-recommended security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, XSS protection).
 *    - Enforces JSON payload size limits (100kb) preventing DoS via oversized payloads.
 *    - Masks internal error stack traces in production to prevent information disclosure (CWE-200).
 * 2. Kubernetes Probing Architecture:
 *    - `/healthz` (Liveness): Validates the Node.js event loop and HTTP server are responsive.
 *    - `/readyz` (Readiness): Validates the container is accepting traffic.
 *    - `/api/health` (Deep Check): Comprehensive dependency inspection (PostgreSQL & Redis).
 * 3. Observability & SRE:
 *    - Integrates Prometheus metrics on `/metrics` and automated latency/request middleware.
 *    - Structured request logging for centralized audit trails (Elasticsearch / Loki).
 * 4. Zero-Downtime Deployment & Graceful Shutdown:
 *    - Handles SIGTERM and SIGINT natively to drain in-flight HTTP requests and cleanly
 *      terminate PostgreSQL pools and Redis sockets during Kubernetes rolling updates.
 */

import 'dotenv/config';
import express from 'express';
import { pool, queryRecords, initSchema } from './src/db.js';
import { redis } from './src/cache.js';
import { deepHealthCheck } from './src/health.js';
import { metricsMiddleware, metricsEndpoint } from './src/metrics.js';

const app = express();

// Security Principle: Prevent technology fingerprinting
app.disable('x-powered-by');

// Security Principle: Enforce browser security headers (OWASP Secure Headers Project)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// DevSecOps Principle: Unified audit logging of HTTP requests and duration
app.use((req, res, next) => {
  const start = performance.now();
  res.on('finish', () => {
    const durationMs = Math.round(performance.now() - start);
    console.info(
      `[${new Date().toISOString()}] [HTTP] ${req.method} ${req.originalUrl || req.url} ${res.statusCode} ${durationMs}ms`,
    );
  });
  next();
});

// Observability Principle: Prometheus metrics middleware applied globally
app.use(metricsMiddleware);

// Security Principle: Denial of Service (DoS) protection via bounded payload sizes
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

/**
 * Authentication middleware for sensitive operational endpoints (NIST SP 800-53 AC-3).
 * Requires valid X-API-Key header or Bearer authorization token when API_AUTH_TOKEN is configured.
 * Fails closed: in production, missing token configuration is a critical configuration error (HTTP 500).
 * In non-production, anonymous access is rejected (HTTP 401) unless ALLOW_ANONYMOUS_ACCESS=true is set.
 */
export const requireApiKey = (req, res, next) => {
  const configuredToken = process.env.API_AUTH_TOKEN || process.env.API_KEY;
  if (!configuredToken) {
    if (process.env.NODE_ENV === 'production') {
      return res.status(500).json({
        error: 'Configuration Error',
        message: 'API authentication token is not configured on server',
      });
    }
    if (process.env.ALLOW_ANONYMOUS_ACCESS === 'true') {
      return next();
    }
    return res.status(401).json({
      error: 'Unauthorized',
      message:
        'API authentication required. Configure API_AUTH_TOKEN or set ALLOW_ANONYMOUS_ACCESS=true for local dev',
    });
  }
  const authHeader = req.headers['x-api-key'] || req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

  if (!token || token !== configuredToken) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid X-API-Key header or Bearer authorization token required',
    });
  }
  next();
};

/**
 * Root service endpoint.
 * Returns basic service metadata, container hostname (pod identification), and version.
 */
app.get('/', (req, res) => {
  res.status(200).json({
    message: 'Hello from a container!',
    service: 'devsecops-demo-api',
    pod: process.env.HOSTNAME || 'unknown',
    timestamp: new Date().toISOString(),
    version: process.env.APP_VERSION || '1.0.0',
  });
});

/**
 * Deep health check endpoint.
 * Evaluates operational status of downstream backing services (PostgreSQL & Redis).
 * Returns HTTP 200 if all services healthy, HTTP 503 if any service degraded.
 * Sanitized to adhere to Least Privilege (no internal addresses or stack disclosures).
 */
app.get('/api/health', async (req, res) => {
  try {
    const health = await deepHealthCheck();
    const statusCode = health.status === 'ok' ? 200 : 503;
    return res.status(statusCode).json({
      status: health.status,
      timestamp: health.timestamp,
      services: {
        postgres: health.services?.postgres?.status || 'unknown',
        redis: health.services?.redis?.status || 'unknown',
      },
    });
  } catch (_error) {
    return res.status(503).json({
      status: 'degraded',
      timestamp: new Date().toISOString(),
    });
  }
});

/**
 * Audit log query endpoint with parameterized query protection.
 *
 * DevSecOps Principle (OWASP A03:2021 / CWE-89):
 * Accepts validated 'id' (integer), 'search' (string), and 'limit' (integer) query parameters.
 * Uses parameterized prepared statements exclusively.
 * Returns HTTP 200 with matching records, or HTTP 400 for invalid inputs.
 */
app.get('/api/records', requireApiKey, async (req, res, next) => {
  try {
    const { id, search, limit } = req.query;

    const DECIMAL_INT_REGEX = /^[1-9]\d*$/;

    // Validate ID if supplied (strict decimal positive integer)
    if (id !== undefined && id !== '') {
      const strId = String(id).trim();
      if (!DECIMAL_INT_REGEX.test(strId) || !Number.isSafeInteger(Number(strId))) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Parameter "id" must be a positive integer',
        });
      }
    }

    // Validate limit if supplied (strict decimal positive integer)
    if (limit !== undefined && limit !== '') {
      const strLimit = String(limit).trim();
      if (!DECIMAL_INT_REGEX.test(strLimit) || !Number.isSafeInteger(Number(strLimit))) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Parameter "limit" must be a positive integer',
        });
      }
    }

    // Validate search string length
    if (search !== undefined && typeof search === 'string' && search.length > 100) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Parameter "search" exceeds maximum length of 100 characters',
      });
    }

    const records = await queryRecords({ id, search, limit });
    return res.status(200).json({
      count: records.length,
      records,
    });
  } catch (error) {
    if (error.status === 400) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.message,
      });
    }
    return next(error);
  }
});

/**
 * Kubernetes Liveness Probe endpoint.
 * Fast, non-blocking check verifying the process is alive and event loop is responsive.
 */
app.get('/healthz', (req, res) => {
  res.status(200).send('ok');
});

export let isReady = false;

export const setReadyState = (ready) => {
  isReady = Boolean(ready);
};

/**
 * Kubernetes Readiness Probe endpoint.
 * Indicates whether the pod has initialized its schema and is ready for traffic.
 */
app.get('/readyz', (req, res) => {
  if (!isReady || isShuttingDown) {
    return res.status(503).send('not ready');
  }
  res.status(200).send('ready');
});

/**
 * Prometheus metrics scrape endpoint.
 * Scraped periodically by Prometheus Operator / collector agents.
 */
app.get('/metrics', metricsEndpoint);

/**
 * System diagnostic status endpoint (NIST SP 800-53 AC-3).
 * Requires API key authorization to prevent information disclosure.
 * Reports Node.js runtime information, process uptime, memory consumption, and environment.
 */
app.get('/api/status', requireApiKey, (req, res) => {
  res.status(200).json({
    uptime: Math.floor(process.uptime()),
    nodeVersion: process.version,
    memoryUsage: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development',
  });
});

/**
 * Global error-handling middleware.
 *
 * DevSecOps Principle:
 * Prevents Information Disclosure (CWE-200) by suppressing stack traces in production.
 */
app.use((err, req, res, _next) => {
  console.error('[AppError]', err);
  const isProduction = process.env.NODE_ENV === 'production';
  const statusCode = err.status || err.statusCode || 500;

  res.status(statusCode).json({
    error: isProduction ? 'Internal Server Error' : err.message,
    ...(isProduction ? {} : { stack: err.stack }),
  });
});

const parsePort = (val, defaultPort) => {
  if (!val) return defaultPort;
  const num = Number(val);
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    throw new Error(
      `Invalid PORT configuration: "${val}". Must be an integer between 1 and 65535.`,
    );
  }
  return num;
};

// Configure listening port with strict integer range validation
const PORT = parsePort(process.env.PORT, 3000);

/**
 * Asynchronous bounded retry loop for database schema initialization on startup.
 * Guarantees resilient recovery if PostgreSQL is temporarily booting, while keeping
 * the liveness probe responsive and deferring readiness until schema initialization succeeds.
 *
 * @param {number} maxAttempts
 * @param {number} delayMs
 * @returns {Promise<boolean>}
 */
export const bootstrapSchemaWithRetry = async (maxAttempts = 15, delayMs = 2000) => {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (isShuttingDown) {
      return false;
    }
    try {
      const ok = await initSchema();
      if (ok) {
        isReady = true;
        console.info(
          `[Server] Database schema initialized on attempt ${attempt}; readiness probe is ready`,
        );
        return true;
      }
    } catch (err) {
      console.warn(
        `[Server] Database schema initialization attempt ${attempt}/${maxAttempts} failed: ${err.message}`,
      );
    }
    if (attempt < maxAttempts && !isShuttingDown) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  console.warn(
    '[Server] Database schema initialization deferred after maximum retry attempts; readiness probe remains 503',
  );
  return false;
};

export let server = null;

if (process.env.NODE_ENV !== 'test') {
  server = app.listen(PORT, () => {
    console.info(
      `[Server] devsecops-demo-api listening on port ${PORT} (NODE_ENV: ${process.env.NODE_ENV || 'development'})`,
    );
    bootstrapSchemaWithRetry().catch((err) => {
      console.error('[Server] Unhandled bootstrap error:', err.message);
    });
  });
}

/**
 * Graceful shutdown coordinator.
 *
 * DevSecOps Principle:
 * Ensures zero-downtime rolling updates in Kubernetes:
 * 1. Stops accepting new inbound HTTP requests.
 * 2. Allows existing in-flight connections to complete cleanly.
 * 3. Gracefully closes PostgreSQL connection pool and Redis connections.
 * 4. Imposes a 10s deadline to prevent zombie processes blocking pod eviction.
 */
let isShuttingDown = false;

const gracefulShutdown = async (signal) => {
  if (isShuttingDown) {
    return;
  }
  isShuttingDown = true;
  isReady = false;
  console.warn(`[Shutdown] Received ${signal}. Initiating graceful shutdown...`);

  // Forceful exit watchdog timer (10 seconds)
  const forceExitTimeout = setTimeout(() => {
    console.error('[Shutdown] Forceful shutdown timeout exceeded (10s). Terminating process.');
    process.exit(1);
  }, 10000);
  forceExitTimeout.unref();

  const closeServer = () =>
    new Promise((resolve) => {
      if (!server || !server.listening) {
        return resolve();
      }
      server.close((err) => {
        if (err) {
          console.error('[Shutdown] Error while closing HTTP server:', err.message);
        } else {
          console.info('[Shutdown] HTTP server closed successfully.');
        }
        resolve();
      });
    });

  await closeServer();

  try {
    console.info('[Shutdown] Closing PostgreSQL connection pool...');
    await pool.end();
    console.info('[Shutdown] PostgreSQL connection pool closed.');
  } catch (dbErr) {
    console.error('[Shutdown] Error closing PostgreSQL pool:', dbErr.message);
  }

  try {
    console.info('[Shutdown] Closing Redis client connection...');
    await redis.quit();
    console.info('[Shutdown] Redis client disconnected.');
  } catch (redisErr) {
    console.error('[Shutdown] Error disconnecting Redis client:', redisErr.message);
  }

  console.info('[Shutdown] Graceful cleanup completed. Exiting process.');
  process.exit(0);
};

// Register signal handlers for Kubernetes pod termination (SIGTERM) and local dev (SIGINT)
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

export default app;
