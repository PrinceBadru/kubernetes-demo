import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';

describe('HTTP Routing & Security Baseline', () => {
  let server;
  let baseUrl;

  before(async () => {
    process.env.NODE_ENV = 'test';
    const mod = await import('../../index.js');
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

    it('GET /readyz should return 200 ready for readiness probe', async () => {
      const res = await fetch(`${baseUrl}/readyz`);
      assert.equal(res.status, 200);
      const text = await res.text();
      assert.equal(text, 'ready');
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
  });
});
