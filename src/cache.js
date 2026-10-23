/**
 * @fileoverview Redis Cache Client & Health Check Module
 *
 * DevSecOps Principles:
 * 1. Resilient Connection Handling:
 *    Uses exponential backoff retry strategy and replica failover awareness (reconnectOnError)
 *    to sustain Kubernetes pod lifecycles, service restarts, and Redis failovers.
 * 2. Rapid Failure Isolation (Circuit Breaking):
 *    Bounded `checkRedis()` execution with a 2000ms deadline prevents network partitions
 *    from causing cascading health-probe timeouts.
 * 3. Graceful Error Handling:
 *    Registers top-level error event handlers preventing uncaught exceptions from
 *    terminating the application process when the cache is transiently unavailable.
 * 4. Observability:
 *    Instruments command counts with Prometheus metrics to measure cache throughput.
 */

import Redis from 'ioredis';
import { redisCommandsTotal } from './metrics.js';

const isTest = process.env.NODE_ENV === 'test';

// Configuration: prefer connection URI or individual parameters
const redisUrl = process.env.REDIS_URL;

const parsePort = (val, defaultPort) => {
  if (!val) return defaultPort;
  const num = Number(val);
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    throw new Error(
      `Invalid port configuration: "${val}". Must be an integer between 1 and 65535.`,
    );
  }
  return num;
};

const connectionOptions = {
  host: process.env.REDIS_HOST || 'localhost',
  port: parsePort(process.env.REDIS_PORT, 6379),
  password: process.env.REDIS_PASSWORD || undefined,
  lazyConnect: true,
  enableOfflineQueue: false,
  maxRetriesPerRequest: 1,
  commandTimeout: 2000,
  enableReadyCheck: true,
  retryStrategy: (times) => {
    if (isTest) {
      return null;
    }
    // Exponential backoff capped at 3000ms to allow recovery without storming the server
    const delay = Math.min(times * 150, 3000);
    return delay;
  },
  reconnectOnError: (err) => {
    if (isTest) {
      return false;
    }
    // Reconnect on failover or readonly error during Sentinel/Cluster switchovers
    if (err.message.includes('READONLY')) {
      return true;
    }
    return false;
  },
};

/**
 * Redis client instance.
 */
export const redis = redisUrl
  ? new Redis(redisUrl, {
      lazyConnect: isTest,
      enableOfflineQueue: !isTest,
      maxRetriesPerRequest: connectionOptions.maxRetriesPerRequest,
      commandTimeout: 2000,
      retryStrategy: connectionOptions.retryStrategy,
    })
  : new Redis(connectionOptions);

// Lifecycle and error event listeners for non-lethal connection error handling
redis.on('connect', () => {
  console.info('[Redis] Connection established');
});

redis.on('ready', () => {
  console.info('[Redis] Ready to process commands');
});

redis.on('reconnecting', (delay) => {
  console.warn(`[Redis] Connection lost. Reconnecting in ${delay}ms...`);
});

redis.on('error', (err) => {
  // Log error without crashing process; app should degrade gracefully if cache is down
  console.error('[Redis] Client connection error:', err.message);
});

/**
 * Executes a Redis health probe (`PING`) with a strict 2-second timeout.
 *
 * DevSecOps Rationale:
 * Enforces a bounded latency window so health checks fail fast if Redis is partitioned,
 * allowing Kubernetes services to route traffic only to fully operational pods.
 *
 * @returns {Promise<{ ok: boolean, latencyMs: number, error?: string }>}
 */
export const checkRedis = async () => {
  const start = performance.now();
  let timerId;

  const timeoutPromise = new Promise((_, reject) => {
    timerId = setTimeout(() => {
      reject(new Error('Redis health check probe timed out after 2000ms'));
    }, 2000);
  });

  try {
    redisCommandsTotal.inc({ command: 'ping' });
    const reply = await Promise.race([redis.ping(), timeoutPromise]);

    const latencyMs = Math.round(performance.now() - start);
    const ok = reply === 'PONG';
    return { ok, latencyMs };
  } catch (error) {
    const latencyMs = Math.round(performance.now() - start);
    console.error('[Redis] Health check failed:', error.message);
    if (error.message.includes('timed out')) {
      try {
        // Disconnect immediately to drop hung socket and purge queued commands (F-09)
        redis.disconnect(true);
      } catch (_) {}
    }
    return { ok: false, latencyMs, error: error.message };
  } finally {
    clearTimeout(timerId);
  }
};

export default {
  redis,
  checkRedis,
};
