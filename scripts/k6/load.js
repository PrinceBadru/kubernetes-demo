/**
 * @fileoverview k6 Load Test Suite for devsecops-demo-api
 *
 * DevSecOps Principle: Non-Functional Requirements (NFR) & Resilience Verification
 *
 * Overview:
 * This load test evaluates service throughput, latency distributions (p90, p95, p99),
 * and resource utilization under sustained concurrent load. It exercises the Horizontal
 * Pod Autoscaler (HPA) operating range (2-5 replicas), connection pooling to PostgreSQL
 * (port 5432) and Redis (port 6379), and ensures compliance with enterprise Service Level
 * Objectives (SLOs).
 *
 * Test Execution Stages:
 * 1. Warm-up / Ramp-up: 0 to 10 VUs over 30s
 * 2. Peak Steady-State: 25 VUs over 1m (exercises HPA scaling threshold)
 * 3. Ramp-down: 25 to 0 VUs over 30s
 *
 * SLOs & Quality Gates:
 * - Error rate: < 1% (http_req_failed rate < 0.01)
 * - 95th Percentile Response Time: < 300ms
 * - 99th Percentile Response Time: < 500ms
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metric: failure rate tracking
export const errorRate = new Rate('error_rate');

export const options = {
  stages: [
    { duration: '30s', target: 10 }, // Ramp-up to baseline traffic
    { duration: '1m', target: 25 },  // Sustained load triggering HPA evaluation
    { duration: '30s', target: 0 },  // Graceful ramp-down
  ],
  thresholds: {
    // DevSecOps SLO Gate: Error budget enforcement (< 1% failures)
    http_req_failed: ['rate<0.01'],
    // DevSecOps SLO Gate: Latency percentiles
    http_req_duration: ['p(95)<300', 'p(99)<500'],
    // Custom error rate threshold
    error_rate: ['rate<0.01'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  const headers = { 'User-Agent': 'k6-load-test/1.0.0' };

  // 1. Root Service Endpoint
  const rootRes = http.get(`${BASE_URL}/`, { headers });
  const rootOk = check(rootRes, {
    'root status is 200': (r) => r.status === 200,
    'root response time < 250ms': (r) => r.timings.duration < 250,
  });
  errorRate.add(!rootOk);

  // 2. Deep Dependency Health Check (/api/health)
  // Queries backing PostgreSQL pool and Redis cache connection
  const healthRes = http.get(`${BASE_URL}/api/health`, { headers });
  const healthOk = check(healthRes, {
    'deep health status is 200 or 503': (r) => r.status === 200 || r.status === 503,
  });
  errorRate.add(!healthOk);

  // 3. Prometheus Metrics Scraping Simulation (/metrics)
  const metricsRes = http.get(`${BASE_URL}/metrics`, { headers });
  const metricsOk = check(metricsRes, {
    'metrics status is 200': (r) => r.status === 200,
  });
  errorRate.add(!metricsOk);

  // 4. Liveness Probe Ping (/healthz)
  const livenessRes = http.get(`${BASE_URL}/healthz`, { headers });
  const livenessOk = check(livenessRes, {
    'healthz status is 200': (r) => r.status === 200,
  });
  errorRate.add(!livenessOk);

  // Simulated think time between user iterations (100ms - 500ms)
  sleep(Math.random() * 0.4 + 0.1);
}

/**
 * Summary handler for exporting structured JSON results.
 */
export function handleSummary(data) {
  return {
    'reports/load-summary.json': JSON.stringify(data, null, 2),
  };
}
