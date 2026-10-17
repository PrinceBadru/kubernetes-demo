/**
 * @fileoverview Deep Health Check Module
 *
 * DevSecOps Principles:
 * 1. Deep Dependency Health Probing vs Lightweight K8s Probes:
 *    Lightweight probes (`/healthz`, `/readyz`) avoid external dependency checks to
 *    prevent cascading restarts during database/cache hiccups. Deep health probes (`/api/health`)
 *    verify all downstream dependencies in parallel to provide end-to-end service status.
 * 2. Parallel Non-Blocking Execution:
 *    Executes PostgreSQL and Redis health checks concurrently with `Promise.all`
 *    ensuring worst-case response latency is bounded by the max single timeout (3s).
 * 3. Synthetic Monitoring & Automated Alerting:
 *    Updates Prometheus gauges (`health_check_status`) on each invocation, feeding
 *    synthetic monitoring pipelines and automated incident alerting.
 * 4. Fault Domain Isolation:
 *    Distinguishes "ok" from "degraded" state, enabling load balancers and mesh routers
 *    to return HTTP 503 Service Unavailable when core dependencies are partitioned.
 */

import { checkPostgres } from './db.js';
import { checkRedis } from './cache.js';
import { healthCheckStatus } from './metrics.js';

/**
 * Performs a deep health inspection of all backing services.
 *
 * DevSecOps Rationale:
 * Running dependency health checks concurrently prevents cumulative timeout latency
 * and accurately surfaces degraded subsystems before serving corrupt or stale data.
 *
 * @returns {Promise<{
 *   status: 'ok' | 'degraded',
 *   timestamp: string,
 *   uptime: number,
 *   services: {
 *     postgres: { status: 'ok' | 'down', latencyMs: number },
 *     redis: { status: 'ok' | 'down', latencyMs: number }
 *   }
 * }>}
 */
export const deepHealthCheck = async () => {
  // Execute checks in parallel to minimize latency
  const [pgResult, redisResult] = await Promise.all([checkPostgres(), checkRedis()]);

  // Update Prometheus gauges for downstream dependency health
  healthCheckStatus.set({ service: 'postgres' }, pgResult.ok ? 1 : 0);
  healthCheckStatus.set({ service: 'redis' }, redisResult.ok ? 1 : 0);

  const isHealthy = pgResult.ok && redisResult.ok;

  return {
    status: isHealthy ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    services: {
      postgres: {
        status: pgResult.ok ? 'ok' : 'down',
        latencyMs: pgResult.latencyMs,
      },
      redis: {
        status: redisResult.ok ? 'ok' : 'down',
        latencyMs: redisResult.latencyMs,
      },
    },
  };
};

export default {
  deepHealthCheck,
};
