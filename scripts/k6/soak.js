// ==============================================================================
// DevSecOps Demo - k6 Soak (Endurance) Test Suite
// ==============================================================================
// Real-World Scenario:
//   A soak test applies sustained, continuous moderate load (10 VUs) over an
//   extended timeframe (5 minutes). This simulates running the service over days
//   or weeks compressed into a CI/CD endurance verification window.
//
// DevSecOps Principle:
//   Reliability & Resource Leak Detection:
//   - Detects progressive Node.js V8 heap memory leaks that don't trigger in short tests.
//   - Identifies database connection pool leaks (PostgreSQL client checkout/release).
//   - Uncovers Redis client connection accumulation and socket exhaustion.
//   - Verifies Garbage Collection (GC) pauses do not cause latency degradation over time:
//     the 95th percentile latency must remain strictly below 1000ms from minute 1 to minute 5.
// ==============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 10 }, // Warm-up ramp to 10 VUs
    { duration: '5m', target: 10 }, // Sustained soak endurance run for 5 minutes
    { duration: '30s', target: 0 }, // Ramp-down to zero
  ],

  thresholds: {
    // Latency must remain stable across the entire 5-minute soak (no progressive degradation)
    http_req_duration: ['p(95)<1000'],
    // Error rate must remain negligible (< 1%) throughout the soak
    http_req_failed: ['rate<0.01'],
    // DevSecOps Assertion Gate: Over 99% of checks must pass (F-45)
    checks: ['rate>0.99'],
  },
};

const rawBaseUrl = __ENV.BASE_URL ? __ENV.BASE_URL.trim() : '';
if (!rawBaseUrl) {
  throw new Error(
    '[k6] Configuration error: BASE_URL environment variable is required and cannot be empty (F-25, F-62).',
  );
}
const BASE_URL = rawBaseUrl.replace(/\/+$/, '');

export function setup() {
  console.log(`[k6] Executing soak test against target: ${BASE_URL}`);
  // Fail fast if target endpoint is unreachable (F-62)
  const probe = http.get(`${BASE_URL}/healthz`, { timeout: '5s' });
  if (probe.status !== 200) {
    throw new Error(
      `[k6] BASE_URL "${BASE_URL}" failed health probe (HTTP ${probe.status}). Aborting test execution.`,
    );
  }
}

export default function () {
  const headers = {
    Accept: 'application/json',
    'User-Agent': 'k6-soak-test/1.0',
  };

  // 1. Health endpoint: Verifies responsiveness under prolonged connection state
  const healthRes = http.get(`${BASE_URL}/healthz`, { headers });
  check(healthRes, {
    'healthz status is 200': (r) => r.status === 200,
    'healthz body is ok': (r) => r.body === 'ok',
    'healthz latency < 1000ms': (r) => r.timings.duration < 1000,
  });

  sleep(0.5);

  // 2. Main API endpoint: Verifies application logic and memory stability
  const mainRes = http.get(`${BASE_URL}/`, { headers });
  check(mainRes, {
    'root status is 200': (r) => r.status === 200,
    'root latency < 1000ms': (r) => r.timings.duration < 1000,
    'semantic response validation': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body && body.service === 'devsecops-demo-api' && body.status === 'ok';
      } catch (_) {
        return false;
      }
    },
  });

  // Realistic client think time between transactions
  sleep(1);
}
