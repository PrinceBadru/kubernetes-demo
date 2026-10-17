import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  register,
  httpRequestsTotal,
  dbPoolActiveConnections,
  healthCheckStatus,
} from '../src/metrics.js';

describe('Metrics Module', () => {
  it('should initialize Prometheus registry with custom metrics', async () => {
    assert.ok(register);
    const metricsText = await register.metrics();
    assert.match(metricsText, /http_requests_total/);
    assert.match(metricsText, /http_request_duration_seconds/);
    assert.match(metricsText, /db_pool_active_connections/);
    assert.match(metricsText, /redis_commands_total/);
    assert.match(metricsText, /health_check_status/);
  });

  it('should allow incrementing counters and setting gauges', async () => {
    httpRequestsTotal.inc({ method: 'GET', route: '/healthz', status_code: '200' });
    healthCheckStatus.set({ service: 'postgres' }, 1);
    healthCheckStatus.set({ service: 'redis' }, 1);
    dbPoolActiveConnections.set(5);

    const metricsText = await register.metrics();
    assert.match(metricsText, /health_check_status\{service="postgres"\} 1/);
    assert.match(metricsText, /health_check_status\{service="redis"\} 1/);
    assert.match(metricsText, /db_pool_active_connections 5/);
  });
});
