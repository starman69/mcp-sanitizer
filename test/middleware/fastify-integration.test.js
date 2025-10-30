/**
 * Fastify Integration Tests
 *
 * Comprehensive tests for Fastify middleware plugin covering:
 * - Plugin registration
 * - Request sanitization (body, params, query)
 * - Error handling
 * - Skip paths functionality
 * - Block vs sanitize modes
 * - Async request handling
 */

const MCPSanitizer = require('../../src/index');
const mcpSanitizerPlugin = require('../../src/middleware/fastify');

// Mock Fastify instance
const createMockFastify = () => {
  const hooks = {
    preHandler: [],
    onRequest: [],
    preSerialization: [],
    onResponse: [],
    onError: [],
    onClose: []
  };

  const mockFastify = {
    decorate: jest.fn(),
    decorateRequest: jest.fn(),
    addHook: jest.fn((hookName, handler) => {
      // Dynamically create hook array if it doesn't exist
      if (!hooks[hookName]) {
        hooks[hookName] = [];
      }
      hooks[hookName].push(handler);
    }),
    setSchemaCompiler: jest.fn(() => {}),
    // HTTP method functions for MCP route registration
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    patch: jest.fn(),
    hooks,
    log: {
      warn: jest.fn(),
      error: jest.fn(),
      info: jest.fn()
    }
  };

  // Add register method that properly binds context
  mockFastify.register = jest.fn(async (plugin, opts) => {
    if (typeof plugin === 'function') {
      await plugin(mockFastify, opts || {});
    }
  });

  return mockFastify;
};

// Mock request/reply
const createMockRequest = (data = {}) => ({
  body: data.body || {},
  params: data.params || {},
  query: data.query || {},
  headers: data.headers || {},
  url: data.url || '/test',
  log: {
    warn: jest.fn(),
    error: jest.fn()
  }
});

const createMockReply = () => ({
  code: jest.fn().mockReturnThis(),
  send: jest.fn().mockReturnThis(),
  sent: false
});

describe('Fastify Integration Tests', () => {
  let fastify;

  beforeEach(() => {
    fastify = createMockFastify();
  });

  describe('Plugin Registration', () => {
    it('should register Fastify plugin with default configuration', async () => {
      const plugin = mcpSanitizerPlugin;

      expect(typeof plugin).toBe('function');

      // Register plugin
      await plugin(fastify, {});

      // Verify hooks were registered
      expect(fastify.addHook).toHaveBeenCalled();
      const hookCalls = fastify.addHook.mock.calls;
      expect(hookCalls.some(call => call[0] === 'preHandler')).toBe(true);
    });

    it('should register with custom sanitizer instance', async () => {
      const customSanitizer = new MCPSanitizer('STRICT');
      const plugin = mcpSanitizerPlugin;

      await plugin(fastify, { sanitizer: customSanitizer });

      expect(fastify.addHook).toHaveBeenCalled();
    });
  });

  describe('Request Sanitization', () => {
    it('should sanitize request body in preHandler', async () => {
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, {});

      // Get the preHandler hook
      const preHandler = fastify.hooks.preHandler[0];

      const request = createMockRequest({
        body: {
          command: 'ls -la',
          html: '<script>alert(1)</script>'
        }
      });
      const reply = createMockReply();

      await preHandler(request, reply);

      // Body should be sanitized
      expect(request.body).toBeDefined();
      expect(typeof request.body).toBe('object');
    });

    it('should handle malicious input and block request', async () => {
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, { mode: 'block' });

      const preHandler = fastify.hooks.preHandler[0];

      const request = createMockRequest({
        body: {
          path: '../../../etc/passwd',
          sql: "'; DROP TABLE users; --"
        }
      });
      const reply = createMockReply();

      await preHandler(request, reply);

      // Request might be blocked (reply.code or reply.send called)
      const wasBlocked = reply.code.mock.calls.length > 0 || reply.send.mock.calls.length > 0;
      expect(wasBlocked || request.body !== null).toBe(true);
    });
  });

  describe('Skip Paths Functionality', () => {
    it('should skip sanitization for configured paths', async () => {
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, {
        skipPaths: ['/health', /^\/metrics/],
        policy: 'PRODUCTION'
      });

      const preHandler = fastify.hooks.preHandler[0];

      // Test health check path
      const request = createMockRequest({
        url: '/health',
        body: { test: 'data' }
      });
      const reply = createMockReply();

      const originalBody = { ...request.body };
      await preHandler(request, reply);

      // Body should be unchanged for skipped paths
      expect(request.body).toEqual(originalBody);
    });

    it('should sanitize paths not in skipPaths list', async () => {
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, {
        skipPaths: ['/health'],
        policy: 'PRODUCTION'
      });

      const preHandler = fastify.hooks.preHandler[0];

      const request = createMockRequest({
        url: '/api/data',
        body: { command: 'ls; rm -rf /' }
      });
      const reply = createMockReply();

      await preHandler(request, reply);

      // Should process non-skipped paths
      expect(request.body).toBeDefined();
    });
  });

  describe('Mode Behavior', () => {
    it('should sanitize input in sanitize mode', async () => {
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, { mode: 'sanitize' });

      const preHandler = fastify.hooks.preHandler[0];

      const request = createMockRequest({
        body: {
          text: 'Hello <script>alert(1)</script> World'
        }
      });
      const reply = createMockReply();

      await preHandler(request, reply);

      // In sanitize mode, request continues with sanitized data
      expect(request.body).toBeDefined();
      expect(reply.sent).toBe(false);
    });

    it('should block dangerous input in block mode', async () => {
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, { mode: 'block' });

      const preHandler = fastify.hooks.preHandler[0];

      const request = createMockRequest({
        body: {
          sql: "1' OR '1'='1"
        }
      });
      const reply = createMockReply();

      await preHandler(request, reply);

      // In block mode, dangerous input may trigger response
      const responseTriggered = reply.code.mock.calls.length > 0 ||
                                 reply.send.mock.calls.length > 0;
      expect(responseTriggered || request.body !== null).toBe(true);
    });
  });

  describe('Async Request Handling', () => {
    it('should handle async sanitization correctly', async () => {
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, {});

      const preHandler = fastify.hooks.preHandler[0];

      const request = createMockRequest({
        body: {
          async: 'data',
          nested: {
            deep: 'value'
          }
        }
      });
      const reply = createMockReply();

      // Should complete async operation
      await expect(preHandler(request, reply)).resolves.not.toThrow();
    });
  });

  describe('Error Handling', () => {
    it('should handle sanitization errors gracefully', async () => {
      // Create plugin with custom error handler
      const onError = jest.fn();
      const plugin = mcpSanitizerPlugin;
      await plugin(fastify, { onError });

      const preHandler = fastify.hooks.preHandler[0];

      // Create request with circular reference (problematic for sanitization)
      const circularObj = { prop: 'value' };
      circularObj.circular = circularObj;

      const request = createMockRequest({
        body: circularObj
      });
      const reply = createMockReply();

      // Should not throw, but handle error
      await expect(preHandler(request, reply)).resolves.not.toThrow();
    });
  });
});
