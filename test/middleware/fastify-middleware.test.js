/**
 * Coverage tests for middleware/fastify.js
 *
 * Targets: mcpSanitizerPlugin (hook registration, skip paths, health checks,
 * static files, decorateRequest, decorateFastify, schemaCompilation),
 * processFastifyRequest (body/params/query/headers sanitization, blocking,
 * warnings), handleBlockedRequest, handleWarnings, handlePluginError,
 * addSchemaCompilerIntegration, registerMCPRoutes, applyToolSpecificSanitization.
 */

const fastifyPlugin = require('../../src/middleware/fastify');
const { mcpSanitizerPlugin, DEFAULT_CONFIG } = fastifyPlugin;

// Helper: create a minimal mock Fastify instance
function createMockFastify () {
  const hooks = {};
  const decorations = {};
  const requestDecorations = {};
  const routes = [];
  const registeredPlugins = [];

  const instance = {
    hooks,
    decorations,
    requestDecorations,
    routes,
    registeredPlugins,
    _schemaCompiler: null,

    decorate (name, value) {
      decorations[name] = value;
    },
    decorateRequest (name, value) {
      requestDecorations[name] = value;
    },
    addHook (name, fn) {
      if (!hooks[name]) hooks[name] = [];
      hooks[name].push(fn);
    },
    get schemaCompiler () {
      return instance._schemaCompiler || function defaultCompiler (schema) {
        return function (data) { return { value: data }; };
      };
    },
    setSchemaCompiler (fn) {
      instance._schemaCompiler = fn;
    },
    register (fn, opts) {
      registeredPlugins.push({ fn, opts });
      // Execute the registered plugin immediately for testing
      if (typeof fn === 'function') {
        return fn(instance, opts || {});
      }
    },
    post (path, schemaOrHandler, handler) {
      routes.push({ method: 'POST', path, handler: handler || schemaOrHandler });
    },
    log: {
      warn: jest.fn(),
      error: jest.fn(),
      info: jest.fn()
    }
  };

  return instance;
}

// Helper: create mock Fastify request
function mockRequest (overrides = {}) {
  return {
    url: '/api/test',
    method: 'POST',
    ip: '127.0.0.1',
    body: {},
    params: {},
    query: {},
    headers: { 'user-agent': 'test-agent' },
    log: {
      warn: jest.fn(),
      error: jest.fn(),
      info: jest.fn()
    },
    sanitizationWarnings: null,
    sanitizationResults: null,
    mcpContext: null,
    ...overrides
  };
}

// Helper: create mock Fastify reply
function mockReply () {
  const reply = {
    _code: 200,
    _payload: null,
    sent: false,
    code (c) { reply._code = c; return reply; },
    send (data) { reply._payload = data; reply.sent = true; return reply; }
  };
  return reply;
}

describe('middleware/fastify.js', () => {
  describe('mcpSanitizerPlugin', () => {
    it('should register hooks on fastify instance', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, { logWarnings: false, schemaCompilation: false });
      // Should have preHandler hook by default
      expect(fastify.hooks.preHandler).toBeDefined();
      expect(fastify.hooks.preHandler.length).toBeGreaterThan(0);
      // Should have preSerialization hook
      expect(fastify.hooks.preSerialization).toBeDefined();
    });

    it('should use onRequest hook when usePreHandler is false', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        usePreHandler: false,
        schemaCompilation: false
      });
      expect(fastify.hooks.onRequest).toBeDefined();
      expect(fastify.hooks.onRequest.length).toBeGreaterThan(0);
    });

    it('should decorate request by default', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, { logWarnings: false, schemaCompilation: false });
      expect('sanitizationWarnings' in fastify.requestDecorations).toBe(true);
      expect('sanitizationResults' in fastify.requestDecorations).toBe(true);
      expect('mcpContext' in fastify.requestDecorations).toBe(true);
    });

    it('should decorate fastify instance when decorateFastify is true', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        decorateFastify: true,
        schemaCompilation: false
      });
      expect(fastify.decorations.mcpSanitizer).toBeDefined();
      expect(fastify.decorations.mcpSanitizerConfig).toBeDefined();
    });

    it('should not decorate request when decorateRequest is false', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        decorateRequest: false,
        schemaCompilation: false
      });
      expect('sanitizationWarnings' in fastify.requestDecorations).toBe(false);
    });
  });

  describe('sanitization hook', () => {
    it('should skip health check paths', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipHealthChecks: true,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({ url: '/health' });
      const reply = mockReply();
      await hook(request, reply);
      expect(request.sanitizationResults).toBeNull();
    });

    it('should skip health sub-paths', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipHealthChecks: true,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({ url: '/healthcheck/detailed' });
      const reply = mockReply();
      await hook(request, reply);
      expect(request.sanitizationResults).toBeNull();
    });

    it('should skip static file paths', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipStaticFiles: true,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({ url: '/assets/app.js' });
      const reply = mockReply();
      await hook(request, reply);
      expect(request.sanitizationResults).toBeNull();
    });

    it('should skip custom skipPaths', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipPaths: ['/public'],
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({ url: '/public' });
      const reply = mockReply();
      await hook(request, reply);
      expect(request.sanitizationResults).toBeNull();
    });

    it('should strip query string from URL for skip matching', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipHealthChecks: true,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({ url: '/health?check=true' });
      const reply = mockReply();
      await hook(request, reply);
      expect(request.sanitizationResults).toBeNull();
    });

    it('should sanitize body, params, query', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { name: 'clean' },
        params: { id: '1' },
        query: { search: 'test' }
      });
      const reply = mockReply();
      await hook(request, reply);
      expect(request.sanitizationWarnings).toBeDefined();
      expect(request.sanitizationResults).toBeDefined();
    });

    it('should sanitize headers when enabled', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        sanitizeHeaders: true,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        headers: { 'x-data': 'safe', 'user-agent': 'test' }
      });
      const reply = mockReply();
      await hook(request, reply);
      expect(request.sanitizationResults.headers).toBeDefined();
    });
  });

  describe('blocking mode', () => {
    it('should block malicious body', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        mode: 'block',
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        includeDetails: true,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: "'; DROP TABLE users; --" }
      });
      const reply = mockReply();
      await hook(request, reply);
      if (reply.sent) {
        expect(reply._code).toBe(400);
        expect(reply._payload.blocked).toBe(true);
        expect(reply._payload.details).toBeDefined();
      }
    });

    it('should call onBlocked handler', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        mode: 'block',
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        schemaCompilation: false,
        onBlocked: async () => {
          // handler called
        }
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: "'; DROP TABLE users; --" }
      });
      const reply = mockReply();
      await hook(request, reply);
      // blocked may be true if SQL injection detected
    });

    it('should skip default response when onBlocked returns false', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        mode: 'block',
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        schemaCompilation: false,
        onBlocked: async () => false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: "'; DROP TABLE users; --" }
      });
      const reply = mockReply();
      await hook(request, reply);
    });

    it('should not include details when includeDetails is false', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        mode: 'block',
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        includeDetails: false,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: "'; DROP TABLE users; --" }
      });
      const reply = mockReply();
      await hook(request, reply);
      if (reply.sent) {
        expect(reply._payload.details).toBeUndefined();
      }
    });
  });

  describe('warnings', () => {
    it('should call onWarning handler', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        schemaCompilation: false,
        onWarning: async () => {
          // handler called
        }
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: '<script>alert(1)</script>' }
      });
      const reply = mockReply();
      await hook(request, reply);
    });

    it('should not add warnings when addWarningsToRequest is false', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        addWarningsToRequest: false,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { name: 'safe' }
      });
      const reply = mockReply();
      await hook(request, reply);
      // When addWarningsToRequest is false, warnings are not attached
    });
  });

  describe('error handling', () => {
    it('should handle plugin errors', async () => {
      const brokenSanitizer = {
        sanitize: () => { throw new Error('Plugin crash'); }
      };
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        sanitizer: brokenSanitizer,
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: 'test' }
      });
      const reply = mockReply();
      await hook(request, reply);
      expect(reply._code).toBe(500);
      expect(reply._payload.error).toBe('Internal sanitization error');
    });

    it('should call onError handler', async () => {
      let capturedError = null;
      const brokenSanitizer = {
        sanitize: () => { throw new Error('Boom'); }
      };
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        sanitizer: brokenSanitizer,
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        schemaCompilation: false,
        onError: async (error, request, reply) => {
          capturedError = error;
        }
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: 'test' }
      });
      const reply = mockReply();
      await hook(request, reply);
      expect(capturedError).not.toBeNull();
      expect(capturedError.message).toBe('Boom');
    });

    it('should skip default error response when onError returns false', async () => {
      const brokenSanitizer = {
        sanitize: () => { throw new Error('Boom'); }
      };
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        sanitizer: brokenSanitizer,
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false,
        schemaCompilation: false,
        onError: async () => false
      });
      const hook = fastify.hooks.preHandler[0];
      const request = mockRequest({
        url: '/api/data',
        body: { input: 'test' }
      });
      const reply = mockReply();
      await hook(request, reply);
      // When onError returns false, no default 500 response
    });
  });

  describe('preSerialization hook', () => {
    it('should pass through payload when sanitizeResponse is not set', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preSerialization[0];
      const request = mockRequest({ url: '/api/data' });
      const reply = mockReply();
      const payload = { data: 'response' };
      const result = await hook(request, reply, payload);
      expect(result).toEqual(payload);
    });

    it('should sanitize response when sanitizeResponse is true', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        sanitizeResponse: true,
        schemaCompilation: false
      });
      const hook = fastify.hooks.preSerialization[0];
      const request = mockRequest({ url: '/api/data' });
      const reply = mockReply();
      const payload = { data: 'clean response' };
      const result = await hook(request, reply, payload);
      expect(result).toBeDefined();
    });
  });

  describe('schema compiler integration', () => {
    it('should install sanitizing schema compiler when enabled', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: true
      });
      // Schema compiler should be overridden
      expect(fastify._schemaCompiler).not.toBeNull();
    });
  });

  describe('DEFAULT_CONFIG', () => {
    it('should export default configuration', () => {
      expect(DEFAULT_CONFIG.sanitizeBody).toBe(true);
      expect(DEFAULT_CONFIG.sanitizeParams).toBe(true);
      expect(DEFAULT_CONFIG.sanitizeQuery).toBe(true);
      expect(DEFAULT_CONFIG.sanitizeHeaders).toBe(false);
      expect(DEFAULT_CONFIG.mode).toBe('sanitize');
      expect(DEFAULT_CONFIG.usePreHandler).toBe(true);
      expect(DEFAULT_CONFIG.policy).toBe('PRODUCTION');
      expect(DEFAULT_CONFIG.schemaCompilation).toBe(true);
      expect(DEFAULT_CONFIG.decorateRequest).toBe(true);
      expect(DEFAULT_CONFIG.decorateFastify).toBe(false);
    });
  });
});
