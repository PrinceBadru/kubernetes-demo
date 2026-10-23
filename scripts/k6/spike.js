// ==============================================================================
// DevSecOps Demo - k6 Spike Test Suite
// ==============================================================================
// Real-World Scenario:
//   Simulates an abrupt, explosive traffic surge—such as a flash sale, breaking
//   news alert, or mass push notification broadcast—followed by an immediate drop.
//   The system runs at a calm baseline of 5 VUs for 1 minute, suddenly jumps to
//   100 VUs (20x traffic increase) in seconds, sustains the spike for 30 seconds,
//   and immediately drops back to 5 VUs for another minute to measure recovery.
//
// DevSecOps Principle:
//   Disaster Recovery & Fast Self-Healing:
//   - Verifies that sudden connection floods do not cause cascading worker crashes
//     or leave zombie database connections in PostgreSQL.
//   - Measures Time-to-Recovery (TTR): Assesses whether the service immediately
//     recovers low latency and zero errors once the spike subsides, rather than
//     remaining locked up or requiring pod restarts.
// ==============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 5 }, // Baseline steady traffic (5 VUs for 1 minute)
    { duration: '10s', target: 100 }, // Explosive instantaneous spike to 100 VUs
    { duration: '30s', target: 100 }, // Sustain spike load for 30 seconds
    { duration: '10s', target: 5 }, // Sharp drop back to baseline (5 VUs)
    { duration: '1m', target: 5 }, // Monitor system recovery and stabilization for 1 minute
    { duration: '10s', target: 0 }, // Clean teardown
  ],

  thresholds: {
    // Under extreme instant shock, error rate must not exceed 10%
    http_req_failed: ['rate<0.10'],
    // 95% of responses must resolve within 2500ms
    http_req_duration: ['p(95)<2500'],
    // DevSecOps Assertion Gate: Over 95% of assertions must pass under spike conditions (F-45)
    checks: ['rate>0.95'],
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
  console.log(`[k6] Executing spike test against target: ${BASE_URL}`);
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
    'User-Agent': 'k6-spike-test/1.0',
  };

  const res = http.get(`${BASE_URL}/`, { headers });

  check(res, {
    'request succeeded or throttled cleanly': (r) => r.status === 200 || r.status === 429,
    'no internal server errors': (r) => r.status < 500,
    'semantic response validation': (r) => {
      if (r.status === 429) return true; // cleanly throttled
      if (r.status !== 200) return false;
      try {
        const body = JSON.parse(r.body);
        return body && body.service === 'devsecops-demo-api' && body.status === 'ok';
      } catch (_) {
        return false;
      }
    },
  });

  // Short pause between iterations
  sleep(0.3);
}
