import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { deepHealthCheck } from '../../src/health.js';
import { healthCheckStatus } from '../../src/metrics.js';
import { redis } from '../../src/cache.js';

describe('Deep Health Check Subsystem', () => {
  after(async () => {
    try {
      redis.disconnect();
    } catch {
      // ignore
    }
  });
  it('should return a structured health report containing timestamp, uptime, and services', async () => {
    const result = await deepHealthCheck();

    assert.ok(result);
    assert.ok(result.status === 'ok' || result.status === 'degraded');
    assert.equal(typeof result.timestamp, 'string');
    assert.equal(typeof result.uptime, 'number');
    assert.ok(result.services.postgres);
    assert.ok(result.services.redis);
    assert.equal(typeof result.services.postgres.status, 'string');
    assert.equal(typeof result.services.redis.status, 'string');
  });

  it('should accurately reflect downstream dependency health in Prometheus gauges', async () => {
    // When deepHealthCheck runs, it updates Prometheus healthCheckStatus gauges
    const result = await deepHealthCheck();

    // Verify gauge metric is populated with values
    const metric = await healthCheckStatus.get();
    assert.ok(metric.values.length >= 2);

    const pgValue = metric.values.find((v) => v.labels.service === 'postgres');
    const redisValue = metric.values.find((v) => v.labels.service === 'redis');

    assert.ok(pgValue);
    assert.ok(redisValue);

    // Assert gauge values deterministically reflect inspected service status
    assert.equal(pgValue.value, result.services.postgres.status === 'ok' ? 1 : 0);
    assert.equal(redisValue.value, result.services.redis.status === 'ok' ? 1 : 0);
  });
});
