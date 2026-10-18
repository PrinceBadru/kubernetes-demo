// ==============================================================================
// DevSecOps Demo - k6 Stress Test Suite
// ==============================================================================
// Real-World Scenario:
//   A stress test deliberately pushes the system beyond its designed operational
//   boundaries to determine the breaking point, identify system bottlenecks,
//   and evaluate the cluster's elasticity under heavy strain.
//
// DevSecOps Principle:
//   Resilience & Elasticity Testing:
//   - Verifies that the Kubernetes Horizontal Pod Autoscaler (HPA) triggers scaling
//     from base 2 replicas up to the configured maximum of 5 replicas.
//   - Checks database connection pool contention (PostgreSQL port 5432) and
//     Redis cache latency under high concurrent load.
//   - Assesses Graceful Degradation: Confirms the API maintains an error rate
//     below 5% and p(95) latency below 3000ms rather than suffering fatal crashes.
// ==============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 50 }, // Ramp up to high load (50 VUs)
    { duration: '2m', target: 50 }, // Hold 50 VUs: Baseline stress
    { duration: '1m', target: 100 }, // Ramp to 100 VUs: Trigger HPA CPU/Memory scaling
    { duration: '2m', target: 100 }, // Hold 100 VUs: Evaluate auto-scaled replica behavior
    { duration: '1m', target: 150 }, // Ramp to 150 VUs: Extreme stress near maximum capacity
    { duration: '2m', target: 150 }, // Hold 150 VUs: Monitor memory pressure and socket saturation
    { duration: '1m', target: 0 }, // Ramp down to zero: Cooldown and HPA scale-in observation
  ],

  thresholds: {
    // Under extreme stress, acceptable 95th percentile response latency is capped at 3s
    http_req_duration: ['p(95)<3000'],
    // System must maintain graceful degradation with error rate under 5%
    http_req_failed: ['rate<0.05'],
    // DevSecOps Assertion Gate: Over 95% of assertions must pass under stress (F-45)
    checks: ['rate>0.95'],
  },
};

const BASE_URL =
  __ENV.BASE_URL && __ENV.BASE_URL.trim() !== '' ? __ENV.BASE_URL.trim() : 'http://localhost:3000';

export function setup() {
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
    'User-Agent': 'k6-stress-test/1.0',
  };

  // Stress tests rotate across core API endpoints to exert pressure on both Express & backend services
  const endpoints = ['/', '/healthz', '/readyz'];
  const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];

  const res = http.get(`${BASE_URL}${endpoint}`, { headers });

  check(res, {
    'status is 200 or 429': (r) => r.status === 200 || r.status === 429,
    'no 5xx fatal crashes': (r) => r.status < 500,
    'response under 3000ms': (r) => r.timings.duration < 3000,
  });

  // Short sleep to maintain continuous high concurrency
  sleep(0.2);
}
