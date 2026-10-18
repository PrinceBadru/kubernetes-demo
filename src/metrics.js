/**
 * @fileoverview Prometheus Metrics Instrumentation Module
 *
 * DevSecOps Principles:
 * 1. Observability & SRE Best Practices:
 *    Exposes the Golden Signals (Latency, Traffic, Errors, Saturation) enabling
 *    Kubernetes Horizontal Pod Autoscaler (HPA), Prometheus alert rules, and
 *    Service Level Objective (SLO) tracking.
 * 2. Cardinality Protection (Denial of Service mitigation):
 *    Route paths are normalized to parameterized templates (e.g. `/api/health`)
 *    rather than raw URLs to prevent cardinality explosions in the time-series database.
 * 3. Health & Dependency Telemetry:
 *    Provides continuous metrics on downstream dependency health (PostgreSQL, Redis)
 *    to trigger automated alerting before service disruptions impact end-users.
 */

import promClient from 'prom-client';

// Initialize default Node.js runtime metrics (GC, memory, event loop, CPU)
promClient.collectDefaultMetrics({
  timeout: 5000,
});

/**
 * Total count of HTTP requests processed by method, route, and status code.
 * Used to calculate request rates (Traffic) and 4xx/5xx error rates (Errors).
 */
export const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests processed',
  labelNames: ['method', 'route', 'status_code'],
});

/**
 * HTTP request latency histogram.
 * Used to calculate p50, p95, p99 latencies (Latency signal).
 */
export const httpRequestDurationSeconds = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
});

/**
 * Active database connection gauge for PostgreSQL connection pool.
 * Used to detect pool exhaustion and connection leaks (Saturation signal).
 */
export const dbPoolActiveConnections = new promClient.Gauge({
  name: 'db_pool_active_connections',
  help: 'Number of active PostgreSQL connection pool connections currently leased',
});

/**
 * PostgreSQL query latency histogram.
 * Captures query performance and identifies slow queries impacting application response times.
 */
export const dbQueryDurationSeconds = new promClient.Histogram({
  name: 'db_query_duration_seconds',
  help: 'Duration of PostgreSQL queries in seconds',
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
});

/**
 * Total Redis commands executed counter.
 * Tracks cache access patterns and command volume.
 */
export const redisCommandsTotal = new promClient.Counter({
  name: 'redis_commands_total',
  help: 'Total number of Redis commands executed',
  labelNames: ['command'],
});

/**
 * Health check status gauge for dependent services (PostgreSQL, Redis).
 * Values: 1 = UP, 0 = DOWN.
 * Critical for synthetic monitoring and alerting in Prometheus/Grafana.
 */
export const healthCheckStatus = new promClient.Gauge({
  name: 'health_check_status',
  help: 'Status of downstream dependencies (1=up, 0=down)',
  labelNames: ['service'],
});

/**
 * Express middleware to automatically track request rate, status, and duration metrics.
 *
 * DevSecOps Rationale:
 * Automated telemetry collection guarantees that all inbound traffic is accounted for
 * without requiring individual route handlers to manually instrument their endpoints.
 *
 * @param {import('express').Request} req - Express request
 * @param {import('express').Response} res - Express response
 * @param {import('express').NextFunction} next - Next middleware function
 */
export const metricsMiddleware = (req, res, next) => {
  const startTime = process.hrtime.bigint();

  res.on('finish', () => {
    const endTime = process.hrtime.bigint();
    const durationSeconds = Number(endTime - startTime) / 1e9;

    // Use normalized route pattern if available to prevent high cardinality metric explosion
    // Unmatched paths (404 Not Found) collapse to __unmatched__ to prevent DoS via label explosion
    let route = 'unknown';
    if (req.route?.path) {
      route = req.baseUrl ? `${req.baseUrl}${req.route.path}` : req.route.path;
    } else if (res.statusCode === 404) {
      route = '__unmatched__';
    }

    const method = req.method;
    const statusCode = res.statusCode.toString();

    httpRequestDurationSeconds.observe({ method, route }, durationSeconds);
    httpRequestsTotal.inc({ method, route, status_code: statusCode });
  });

  next();
};

/**
 * Prometheus metrics scrape endpoint handler.
 * Exposes all registered metrics in standard Prometheus text format.
 *
 * DevSecOps Rationale:
 * Exposing metrics on a standardized path (/metrics) enables Kubernetes-native
 * scraping via Prometheus Operator / PodMonitor / ServiceMonitor.
 *
 * @param {import('express').Request} req - Express request
 * @param {import('express').Response} res - Express response
 */
export const metricsEndpoint = async (req, res) => {
  try {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
  } catch (error) {
    res.status(500).end(`Failed to generate Prometheus metrics: ${error.message}`);
  }
};

export const register = promClient.register;

export default {
  register,
  httpRequestsTotal,
  httpRequestDurationSeconds,
  dbPoolActiveConnections,
  dbQueryDurationSeconds,
  redisCommandsTotal,
  healthCheckStatus,
  metricsMiddleware,
  metricsEndpoint,
};
