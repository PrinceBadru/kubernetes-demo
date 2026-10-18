import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';

describe('HTTP Routing & Security Baseline', () => {
  let server;
  let baseUrl;
  let mod;

  before(async () => {
    process.env.NODE_ENV = 'test';
    mod = await import('../../index.js');
    const app = mod.default;

    await new Promise((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  describe('Security Headers (OWASP Recommendations)', () => {
    it('should include required defense-in-depth headers on all responses', async () => {
      const res = await fetch(`${baseUrl}/healthz`);
      assert.equal(res.status, 200);

      // Verify OWASP Secure Headers
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(res.headers.get('x-frame-options'), 'DENY');
      assert.equal(res.headers.get('x-xss-protection'), '1; mode=block');
      assert.equal(
        res.headers.get('strict-transport-security'),
        'max-age=31536000; includeSubDomains',
      );
      assert.equal(res.headers.get('content-security-policy'), "default-src 'self'");

      // Verify technology fingerprinting is stripped
      assert.equal(res.headers.get('x-powered-by'), null);
    });
  });

  describe('Core Service & Kubernetes Probe Endpoints', () => {
    it('GET / should return service identity and container metadata', async () => {
      const res = await fetch(`${baseUrl}/`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get('content-type'), /application\/json/);

      const body = await res.json();
      assert.equal(body.service, 'devsecops-demo-api');
      assert.equal(typeof body.message, 'string');
      assert.equal(typeof body.version, 'string');
      assert.equal(typeof body.pod, 'string');
    });

    it('GET /healthz should return 200 ok for liveness probe', async () => {
      const res = await fetch(`${baseUrl}/healthz`);
      assert.equal(res.status, 200);
      const text = await res.text();
      assert.equal(text, 'ok');
    });

    it('GET /readyz should return 503 when not ready, and 200 when ready', async () => {
      // 1. Initial unready state
      mod.setReadyState(false);
      const resUnready = await fetch(`${baseUrl}/readyz`);
      assert.equal(resUnready.status, 503);
      const textUnready = await resUnready.text();
      assert.equal(textUnready, 'not ready');

      // 2. Initialized ready state
      mod.setReadyState(true);
      const resReady = await fetch(`${baseUrl}/readyz`);
      assert.equal(resReady.status, 200);
      const textReady = await resReady.text();
      assert.equal(textReady, 'ready');
    });

    it('GET /api/status should return process uptime and runtime info', async () => {
      const res = await fetch(`${baseUrl}/api/status`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(typeof body.uptime, 'number');
      assert.equal(typeof body.nodeVersion, 'string');
      assert.equal(typeof body.memoryUsage, 'object');
    });
  });

  describe('Audit Records Route & Input Validation (/api/records)', () => {
    it('GET /api/records?id=invalid should reject non-integer ID with HTTP 400', async () => {
      const res = await fetch(`${baseUrl}/api/records?id=abc`);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.error, 'Validation Error');
      assert.match(body.message, /positive integer/);
    });

    it('GET /api/records?id=1%27%20OR%201=1 should reject SQLi in ID with HTTP 400', async () => {
      const res = await fetch(`${baseUrl}/api/records?id=1' OR '1'='1`);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.error, 'Validation Error');
    });

    it('GET /api/records?limit=invalid should reject non-integer limit with HTTP 400', async () => {
      const res = await fetch(`${baseUrl}/api/records?limit=abc`);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.error, 'Validation Error');
      assert.match(body.message, /positive integer/);
    });

    it('GET /api/records?search=... should reject oversized search strings with HTTP 400', async () => {
      const longString = 'A'.repeat(105);
      const res = await fetch(`${baseUrl}/api/records?search=${longString}`);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.error, 'Validation Error');
      assert.match(body.message, /maximum length/);
    });

    it('GET /non-existent-route should return HTTP 404', async () => {
      const res = await fetch(`${baseUrl}/api/missing-route`);
      assert.equal(res.status, 404);
    });

    it('should enforce API Key authentication when API_AUTH_TOKEN is configured', async () => {
      process.env.API_AUTH_TOKEN = 'test-secret-key-123';
      try {
        // Without key -> 401
        const unauthRes = await fetch(`${baseUrl}/api/records`);
        assert.equal(unauthRes.status, 401);

        // With X-API-Key -> authorized
        const authRes = await fetch(`${baseUrl}/api/records?id=abc`, {
          headers: { 'x-api-key': 'test-secret-key-123' },
        });
        // Passed auth, reached validation logic
        assert.equal(authRes.status, 400);
      } finally {
        delete process.env.API_AUTH_TOKEN;
      }
    });

    it('should collapse unmatched 404 paths to __unmatched__ in metrics to prevent metric explosion', async () => {
      // Send multiple distinct 404 paths
      for (let i = 0; i < 15; i++) {
        const res = await fetch(`${baseUrl}/random-non-existent-path-${i}`);
        assert.equal(res.status, 404);
      }

      // Fetch /metrics and verify cardinality is bounded
      const metricsRes = await fetch(`${baseUrl}/metrics`);
      assert.equal(metricsRes.status, 200);
      const metricsText = await metricsRes.text();

      assert.match(metricsText, /route="__unmatched__"/);
      assert.doesNotMatch(metricsText, /route="\/random-non-existent-path-0"/);
    });
  });
});
