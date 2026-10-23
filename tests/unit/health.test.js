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
    const mockPg = async () => ({ ok: true, latencyMs: 5 });
    const mockRedis = async () => ({ ok: true, latencyMs: 2 });
    const result = await deepHealthCheck({ checkPg: mockPg, checkCache: mockRedis });

    assert.ok(result);
    assert.equal(result.status, 'ok');
    assert.equal(typeof result.timestamp, 'string');
    assert.equal(typeof result.uptime, 'number');
    assert.ok(result.services.postgres);
    assert.ok(result.services.redis);
    assert.equal(result.services.postgres.status, 'ok');
    assert.equal(result.services.redis.status, 'ok');
  });

  it('should deterministically report healthy (status: ok) when all dependencies pass', async () => {
    const mockPg = async () => ({ ok: true, latencyMs: 5 });
    const mockRedis = async () => ({ ok: true, latencyMs: 2 });

    const result = await deepHealthCheck({ checkPg: mockPg, checkCache: mockRedis });

    assert.equal(result.status, 'ok');
    assert.equal(result.services.postgres.status, 'ok');
    assert.equal(result.services.postgres.latencyMs, 5);
    assert.equal(result.services.redis.status, 'ok');
    assert.equal(result.services.redis.latencyMs, 2);

    const metric = await healthCheckStatus.get();
    const pgGauge = metric.values.find((v) => v.labels.service === 'postgres');
    const redisGauge = metric.values.find((v) => v.labels.service === 'redis');
    assert.equal(pgGauge.value, 1);
    assert.equal(redisGauge.value, 1);
  });

  it('should deterministically report degraded when PostgreSQL fails', async () => {
    const mockPg = async () => ({ ok: false, latencyMs: 15, error: 'connection refused' });
    const mockRedis = async () => ({ ok: true, latencyMs: 3 });

    const result = await deepHealthCheck({ checkPg: mockPg, checkCache: mockRedis });

    assert.equal(result.status, 'degraded');
    assert.equal(result.services.postgres.status, 'down');
    assert.equal(result.services.redis.status, 'ok');

    const metric = await healthCheckStatus.get();
    const pgGauge = metric.values.find((v) => v.labels.service === 'postgres');
    const redisGauge = metric.values.find((v) => v.labels.service === 'redis');
    assert.equal(pgGauge.value, 0);
    assert.equal(redisGauge.value, 1);
  });

  it('should deterministically report degraded when Redis fails', async () => {
    const mockPg = async () => ({ ok: true, latencyMs: 4 });
    const mockRedis = async () => ({ ok: false, latencyMs: 2000, error: 'timeout' });

    const result = await deepHealthCheck({ checkPg: mockPg, checkCache: mockRedis });

    assert.equal(result.status, 'degraded');
    assert.equal(result.services.postgres.status, 'ok');
    assert.equal(result.services.redis.status, 'down');

    const metric = await healthCheckStatus.get();
    const pgGauge = metric.values.find((v) => v.labels.service === 'postgres');
    const redisGauge = metric.values.find((v) => v.labels.service === 'redis');
    assert.equal(pgGauge.value, 1);
    assert.equal(redisGauge.value, 0);
  });

  it('should deterministically report degraded and set both Prometheus gauges to 0 when all dependencies fail', async () => {
    const mockPg = async () => ({ ok: false, latencyMs: 15, error: 'connection refused' });
    const mockRedis = async () => ({ ok: false, latencyMs: 2000, error: 'timeout' });

    const result = await deepHealthCheck({ checkPg: mockPg, checkCache: mockRedis });

    assert.equal(result.status, 'degraded');
    assert.equal(result.services.postgres.status, 'down');
    assert.equal(result.services.redis.status, 'down');

    const metric = await healthCheckStatus.get();
    const pgGauge = metric.values.find((v) => v.labels.service === 'postgres');
    const redisGauge = metric.values.find((v) => v.labels.service === 'redis');
    assert.equal(pgGauge.value, 0);
    assert.equal(redisGauge.value, 0);
  });

  it('should handle probe timeouts cleanly without unhandled rejection', async () => {
    const mockTimeoutPg = async () => ({ ok: false, latencyMs: 2500, error: 'timeout' });
    const mockTimeoutRedis = async () => ({ ok: false, latencyMs: 2000, error: 'timeout' });

    const result = await deepHealthCheck({ checkPg: mockTimeoutPg, checkCache: mockTimeoutRedis });
    assert.equal(result.status, 'degraded');
  });
});
