/**
 * @fileoverview k6 Smoke Test Suite for devsecops-demo-api
 *
 * DevSecOps Principle: Shift-Right Continuous Verification & Progressive Gating
 *
 * Overview:
 * The smoke test is a lightweight, low-concurrency sanity check designed to verify
 * that the deployed application is operational and capable of handling traffic
 * under nominal conditions. It executes with a minimal virtual user (VU) footprint
 * before heavy load tests are introduced, catching misconfigurations or crashed services early.
 *
 * SLOs & Thresholds:
 * - 99% of requests must succeed (HTTP status 200).
 * - 95th percentile latency must be under 200ms.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metric: failure rate tracking
export const failureRate = new Rate('failed_requests');

export const options = {
  // Low concurrency: 1 virtual user for a short duration
  vus: 1,
  duration: '30s',
  thresholds: {
    // DevSecOps SLO Gate: Request failure rate must be strictly under 1%
    failed_requests: ['rate<0.01'],
    // DevSecOps SLO Gate: 95% of requests must complete under 200ms
    http_req_duration: ['p(95)<200'],
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
const API_TOKEN = __ENV.API_KEY || __ENV.API_AUTH_TOKEN || 'devsecops-demo-api-key';

export function setup() {
  console.log(`[k6] Executing smoke test against target: ${BASE_URL}`);
  // Fail fast if target endpoint is unreachable (F-62)
  const probe = http.get(`${BASE_URL}/healthz`, { timeout: '5s' });
  if (probe.status !== 200) {
    throw new Error(
      `[k6] BASE_URL "${BASE_URL}" failed health probe (HTTP ${probe.status}). Aborting test execution.`,
    );
  }
}

export default function () {
  const headers = { 'User-Agent': 'k6-smoke-test/1.0.0' };
  const authHeaders = {
    ...headers,
    'x-api-key': API_TOKEN,
  };

  // 1. Validate root API endpoint
  const rootRes = http.get(`${BASE_URL}/`, { headers });
  const rootSuccess = check(rootRes, {
    'root status is 200': (r) => r.status === 200,
    'root contains service identifier': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.service === 'devsecops-demo-api';
      } catch (_e) {
        return false;
      }
    },
  });
  failureRate.add(!rootSuccess);

  // 2. Validate Kubernetes Liveness probe endpoint
  const healthzRes = http.get(`${BASE_URL}/healthz`, { headers });
  const healthzSuccess = check(healthzRes, {
    'healthz status is 200': (r) => r.status === 200,
    'healthz returns ok': (r) => r.body === 'ok',
  });
  failureRate.add(!healthzSuccess);

  // 3. Validate Kubernetes Readiness probe endpoint
  const readyzRes = http.get(`${BASE_URL}/readyz`, { headers });
  const readyzSuccess = check(readyzRes, {
    'readyz status is 200': (r) => r.status === 200,
    'readyz returns ready': (r) => r.body === 'ready',
  });
  failureRate.add(!readyzSuccess);

  // 4. Validate system status diagnostic endpoint
  const statusRes = http.get(`${BASE_URL}/api/status`, { headers: authHeaders });
  const statusSuccess = check(statusRes, {
    'status endpoint is 200': (r) => r.status === 200,
    'status reports node version': (r) => {
      try {
        const body = JSON.parse(r.body);
        return typeof body.nodeVersion === 'string';
      } catch (_e) {
        return false;
      }
    },
  });
  failureRate.add(!statusSuccess);

  sleep(1);
}

/**
 * Summary handler for exporting structured JSON results.
 */
export function handleSummary(data) {
  return {
    'reports/smoke-summary.json': JSON.stringify(data, null, 2),
  };
}
