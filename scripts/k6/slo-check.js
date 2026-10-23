// ==============================================================================
// DevSecOps Demo - k6 SLO (Service Level Objective) Compliance Test Suite
// ==============================================================================
// Real-World Scenario:
//   An automated CI/CD deployment gate / canary evaluation test. Before a newly
//   deployed revision is promoted to receive 100% of production traffic, this test
//   evaluates compliance against legally binding Service Level Agreements (SLAs)
//   and internal Service Level Objectives (SLOs).
//
// DevSecOps Principle:
//   Automated Quality Gate & Canary Validation:
//   - Target SLO 1 (Availability): >= 99.9% successful responses (Three Nines).
//   - Target SLO 2 (Latency): 99th percentile (p99) response time must be < 500ms.
//   - Target SLO 3 (Error Budget): Error rate must not exceed 0.1% (rate < 0.001).
//   - If any metric breaches the SLO thresholds, the automated pipeline halts
//     and triggers an immediate canary rollback.
// ==============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const rawBaseUrl = __ENV.BASE_URL ? __ENV.BASE_URL.trim() : '';
if (!rawBaseUrl) {
  throw new Error(
    '[k6] Configuration error: BASE_URL environment variable is required and cannot be empty (F-25, F-62).',
  );
}
const BASE_URL = rawBaseUrl.replace(/\/+$/, '');

// Custom metrics dedicated to tracking Service Level Indicators (SLIs)
const sloAvailability = new Rate('slo_availability');
const sloLatency = new Trend('slo_latency_duration');
const sloSuccessfulRequests = new Counter('slo_successful_requests');
const sloBreachedRequests = new Counter('slo_breached_requests');

export const options = {
  // Steady-state evaluation load: 20 concurrent users over a 2-minute gate window
  vus: 20,
  duration: '2m',

  thresholds: {
    // SLO Target 1: Availability >= 99.9%
    slo_availability: ['rate>=0.999'],

    // SLO Target 2: Latency p99 < 500ms
    slo_latency_duration: ['p(99)<500'],

    // Standard HTTP metrics strictly mirroring real-world SLA commitments
    http_req_duration: ['p(99)<500', 'p(95)<300', 'avg<150'],
    http_req_failed: ['rate<0.001'], // Maximum 0.1% failures allowed
    // DevSecOps Assertion Gate: Over 99.9% of checks must pass (F-45)
    checks: ['rate>0.999'],
  },
};

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
    'User-Agent': 'k6-slo-validator/1.0',
  };

  const startTime = Date.now();
  const res = http.get(`${BASE_URL}/`, { headers });
  const duration = Date.now() - startTime;

  // Track raw response latency in custom trend metric
  sloLatency.add(duration);

  // Validate response status and latency against SLO objectives
  const isStatusValid = res.status === 200;
  const isLatencyValid = duration < 500;
  const isSloMet = isStatusValid && isLatencyValid;

  // Record availability SLI
  sloAvailability.add(isStatusValid);

  if (isSloMet) {
    sloSuccessfulRequests.add(1);
  } else {
    sloBreachedRequests.add(1);
  }

  check(res, {
    'SLO HTTP status is 200': () => isStatusValid,
    'SLO latency p99 within 500ms': () => isLatencyValid,
    'SLO response structure intact': (r) => r.body && r.body.includes('pod'),
  });

  // Paced sleep simulating organic user transaction intervals
  sleep(0.5);
}
