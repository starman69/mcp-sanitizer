/**
 * Koa Middleware Error Handling Tests
 *
 * Tests for Koa-specific error scenarios, context modifications,
 * and async error boundaries.
 *
 * Priority: MEDIUM - Covers Koa error handling (300+ uncovered lines)
 */

const MCPSanitizer = require('../../src/index');
const { createKoaMiddleware } = require('../../src/middleware/koa');

// Mock Koa context
const createMockContext = (data = {}) => ({
  request: {
    body: data.body || {}
  },
  params: data.params || {},
  query: data.query || {},
  headers: data.headers || {},
  path: data.path || '/test',
  method: data.method || 'GET',
  ip: data.ip || '127.0.0.1',
  status: 200,
  body: null,
  state: {},
  get: (header) => data.headers?.[header.toLowerCase()] || '',
  logger: {
    warn: jest.fn(),
    error: jest.fn(),
    info: jest.fn()
  },
  sanitizationWarnings: [],
  sanitizationResults: {}
});

describe('Koa Middleware Error Handling Tests', () => {
  let sanitizer;

  beforeEach(() => {
    sanitizer = new MCPSanitizer('STRICT');
  });

  describe('Error Propagation', () => {
    it('should handle sanitization errors gracefully', async () => {
      const middleware = createKoaMiddleware({
        sanitizer,
        sanitizeBody: true,
        onError: jest.fn((error, ctx) => { // eslint-disable-line n/handle-callback-err
          // Custom error handler
          ctx.status = 500;
          ctx.body = { error: 'Sanitization failed' };
          return false; // Indicate we handled it
        })
      });

      const ctx = createMockContext({
        body: {
          // Create circular reference (problematic for sanitization)
          circular: null
        }
      });
      ctx.request.body.circular = ctx.request.body;

      const next = jest.fn();

      // Should not throw, but handle error
      await expect(middleware(ctx, next)).resolves.not.toThrow();
    });

    it('should log errors with context information', async () => {
      const onError = jest.fn((err) => {
        // Handle error parameter
        expect(err).toBeDefined();
        return false;
      });
      const middleware = createKoaMiddleware({
        sanitizer,
        onError
      });

      const ctx = createMockContext({
        path: '/api/test',
        method: 'POST',
        ip: '192.168.1.1'
      });

      // Simulate error by making next() throw
      const next = jest.fn().mockRejectedValue(new Error('Test error'));

      await middleware(ctx, next);

      // Error handler should be called with context
      expect(onError).toHaveBeenCalled();
    });

    it('should handle async errors in custom handlers', async () => {
      const middleware = createKoaMiddleware({
        sanitizer,
        onWarning: async (warnings, ctx) => { // eslint-disable-line n/handle-callback-err
          // Simulate async error
          throw new Error('Handler error');
        }
      });

      const ctx = createMockContext({
        body: { html: '<script>alert(1)</script>' }
      });

      const next = jest.fn();

      // Should handle async errors in custom handlers
      await expect(middleware(ctx, next)).resolves.not.toThrow();
    });
  });

  describe('Context Modifications on Block Mode', () => {
    it('should set correct status and body when blocking', async () => {
      const middleware = createKoaMiddleware({
        mode: 'block',
        sanitizer,
        blockStatusCode: 403,
        errorMessage: 'Custom block message'
      });

      const ctx = createMockContext({
        body: {
          sql: "'; DROP TABLE users; --"
        }
      });

      const next = jest.fn();

      await middleware(ctx, next);

      // Should set correct status and body
      expect(ctx.status).toBe(403);
      expect(ctx.body).toBeDefined();
      expect(ctx.body.error).toBe('Custom block message');
      expect(ctx.body.blocked).toBe(true);
    });

    it('should include warning details when configured', async () => {
      const middleware = createKoaMiddleware({
        mode: 'block',
        sanitizer,
        includeDetails: true
      });

      const ctx = createMockContext({
        body: {
          html: '<script>alert(1)</script>',
          sql: "1' OR '1'='1"
        }
      });

      const next = jest.fn();

      await middleware(ctx, next);

      // Should include detailed warnings
      expect(ctx.body.details).toBeDefined();
      expect(Array.isArray(ctx.body.details)).toBe(true);
      expect(ctx.body.details.length).toBeGreaterThan(0);
    });

    it('should add sanitization data to state when configured', async () => {
      const middleware = createKoaMiddleware({
        mode: 'sanitize',
        sanitizer,
        addToState: true,
        contextKey: 'security'
      });

      const ctx = createMockContext({
        body: { text: 'clean data' }
      });

      const next = jest.fn();

      await middleware(ctx, next);

      // Should add to state
      expect(ctx.state.security).toBeDefined();
      expect(ctx.state.security.processed).toBe(true);
      expect(ctx.state.security.warnings).toBeDefined();
    });

    it('should allow custom blocked handler to override response', async () => {
      const onBlocked = jest.fn((warnings, ctx) => {
        ctx.status = 429; // Rate limit
        ctx.body = { custom: 'Custom block response' };
        return false; // We handled it
      });

      const middleware = createKoaMiddleware({
        mode: 'block',
        sanitizer,
        onBlocked
      });

      const ctx = createMockContext({
        body: { command: 'rm -rf /' }
      });

      const next = jest.fn();

      await middleware(ctx, next);

      // Custom handler should be called
      expect(onBlocked).toHaveBeenCalled();
      expect(ctx.status).toBe(429);
      expect(ctx.body.custom).toBe('Custom block response');
    });
  });

  describe('Async Error Boundaries', () => {
    it('should handle errors in next middleware', async () => {
      const middleware = createKoaMiddleware({
        sanitizer,
        onError: jest.fn((error, ctx) => { // eslint-disable-line n/handle-callback-err
          ctx.status = 500;
          ctx.body = { error: 'Internal error' };
          return false;
        })
      });

      const ctx = createMockContext();

      // Next middleware throws
      const next = jest.fn().mockRejectedValue(new Error('Next middleware error'));

      await middleware(ctx, next);

      // Should handle the error from next middleware
      expect(ctx.status).toBe(500);
    });

    it('should handle timeout scenarios', async () => {
      const middleware = createKoaMiddleware({
        sanitizer
      });

      const ctx = createMockContext({
        body: {
          // Very large nested structure
          data: JSON.parse(JSON.stringify({ nested: { deep: { structure: 'a'.repeat(1000) } } }))
        }
      });

      const next = jest.fn();

      const start = Date.now();
      await middleware(ctx, next);
      const elapsed = Date.now() - start;

      // Should complete in reasonable time
      expect(elapsed).toBeLessThan(1000);
      expect(next).toHaveBeenCalled();
    });

    it('should handle concurrent requests safely', async () => {
      const middleware = createKoaMiddleware({
        sanitizer
      });

      // Simulate concurrent requests
      const requests = Array(10).fill(null).map((_, i) => {
        const ctx = createMockContext({
          path: `/test/${i}`,
          body: { test: `data${i}` }
        });
        const next = jest.fn();
        return middleware(ctx, next);
      });

      // All should complete without interference
      await expect(Promise.all(requests)).resolves.not.toThrow();
    });

    it('should handle response sanitization errors', async () => {
      const middleware = createKoaMiddleware({
        sanitizer,
        sanitizeResponse: true
      });

      const ctx = createMockContext();
      ctx.body = { result: 'initial' };

      const next = jest.fn(async () => {
        // Next middleware sets response body
        ctx.body = {
          dangerous: '<script>alert(1)</script>'
        };
      });

      await middleware(ctx, next);

      // Response should be sanitized or blocked
      expect(ctx.body).toBeDefined();
    });

    it('should preserve async call stack for debugging', async () => {
      const errors = [];
      const middleware = createKoaMiddleware({
        sanitizer,
        onError: (err, ctx) => {
          errors.push({ error: err, stack: err.stack });
          return false;
        }
      });

      const ctx = createMockContext();
      const next = jest.fn().mockRejectedValue(new Error('Test error'));

      await middleware(ctx, next);

      // Should capture error with stack trace
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].stack).toBeDefined();
    });
  });

  describe('Skip Paths Error Handling', () => {
    it('should handle skip path regex errors gracefully', async () => {
      // Invalid regex should not crash
      const middleware = createKoaMiddleware({
        sanitizer,
        skipPaths: ['/health', '[invalid-regex']
      });

      const ctx = createMockContext({ path: '/test' });
      const next = jest.fn();

      // Should not throw even with invalid regex
      await expect(middleware(ctx, next)).resolves.not.toThrow();
    });
  });

  describe('Custom Handler Error Cases', () => {
    it('should handle null/undefined from custom handlers', async () => {
      const middleware = createKoaMiddleware({
        sanitizer,
        onWarning: () => null,
        onBlocked: () => undefined
      });

      const ctx = createMockContext({
        body: { html: '<script>alert(1)</script>' }
      });

      const next = jest.fn();

      await middleware(ctx, next);

      // Should handle null/undefined returns gracefully
      expect(ctx).toBeDefined();
    });

    it('should handle errors thrown in custom warning handler', async () => {
      const onError = jest.fn();
      const middleware = createKoaMiddleware({
        sanitizer,
        onWarning: () => { // eslint-disable-line n/handle-callback-err
          throw new Error('Warning handler error');
        },
        onError
      });

      const ctx = createMockContext({
        body: { html: '<script>alert(1)</script>' } // Will trigger warnings
      });

      const next = jest.fn();

      await middleware(ctx, next);

      // Error handler should be called when warning handler throws
      expect(onError).toHaveBeenCalled();
    });
  });
});
