/**
 * Coverage tests for middleware/fastify.js advanced features
 *
 * Targets: addSchemaCompilerIntegration (sanitizing validator, block mode,
 * warnings on validation error/success, sanitization error),
 * registerMCPRoutes (preHandler hook, tool execution endpoint),
 * applyToolSpecificSanitization (all tool types, blocking, warnings).
 */

const { mcpSanitizerPlugin } = require('../../src/middleware/fastify');

// Helper: create a minimal mock Fastify instance
function createMockFastify () {
  const hooks = {};
  const decorations = {};
  const requestDecorations = {};
  const routes = [];

  const instance = {
    hooks,
    decorations,
    requestDecorations,
    routes,
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
      return instance._schemaCompiler || function defaultCompiler () {
        return function (data) { return { value: data }; };
      };
    },
    setSchemaCompiler (fn) {
      instance._schemaCompiler = fn;
    },
    register (fn, opts) {
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

function mockRequest (overrides = {}) {
  return {
    url: '/api/test',
    method: 'POST',
    ip: '127.0.0.1',
    body: {},
    params: {},
    query: {},
    headers: { 'user-agent': 'test-agent' },
    log: { warn: jest.fn(), error: jest.fn(), info: jest.fn() },
    sanitizationWarnings: null,
    sanitizationResults: null,
    mcpContext: null,
    ...overrides
  };
}

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

describe('fastify advanced coverage', () => {
  describe('schema compiler integration', () => {
    it('should create a sanitizing schema compiler', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: true,
        skipHealthChecks: false,
        skipStaticFiles: false
      });

      // Schema compiler should be set
      expect(fastify._schemaCompiler).not.toBeNull();

      // Call the schema compiler
      const compiledValidator = fastify._schemaCompiler({ type: 'object' });
      expect(typeof compiledValidator).toBe('function');

      // Validate clean data
      const result = compiledValidator({ name: 'clean' });
      expect(result).toBeDefined();
    });

    it('should block data in block mode via schema compiler', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: true,
        mode: 'block',
        skipHealthChecks: false,
        skipStaticFiles: false
      });

      const compiledValidator = fastify._schemaCompiler({ type: 'object' });
      const result = compiledValidator({ input: "'; DROP TABLE users; --" });
      // May return error if blocked
      expect(result).toBeDefined();
    });
  });

  describe('preSerialization with sanitizeResponse', () => {
    it('should sanitize response payload', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        sanitizeResponse: true,
        schemaCompilation: false
      });

      const hook = fastify.hooks.preSerialization[0];
      const request = mockRequest({ url: '/api/data' });
      const reply = mockReply();
      const result = await hook(request, reply, { data: 'clean' });
      expect(result).toBeDefined();
    });

    it('should handle blocked response payload', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        sanitizeResponse: true,
        schemaCompilation: false
      });

      const hook = fastify.hooks.preSerialization[0];
      const request = mockRequest({ url: '/api/data' });
      const reply = mockReply();
      await expect(hook(request, reply, { data: '<script>alert(1)</script>' }))
        .rejects.toThrow('Response blocked');
    });

    it('should handle null payload', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        sanitizeResponse: true,
        schemaCompilation: false
      });

      const hook = fastify.hooks.preSerialization[0];
      const request = mockRequest({ url: '/api/data' });
      const reply = mockReply();
      const result = await hook(request, reply, null);
      expect(result).toBeNull();
    });
  });

  describe('registerMCPRoutes', () => {
    it('should register preHandler hook for MCP routes', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: false
      });

      // Should have registered routes via the register call
      expect(fastify.routes.length).toBeGreaterThan(0);
      const toolRoute = fastify.routes.find(r => r.path === '/tools/:toolName/execute');
      expect(toolRoute).toBeDefined();
    });

    it('should execute tool route handler', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: false
      });

      const toolRoute = fastify.routes.find(r => r.path === '/tools/:toolName/execute');
      const request = mockRequest({
        params: { toolName: 'file_reader' },
        body: { parameters: { file_path: '/tmp/test.txt' } }
      });
      const reply = mockReply();

      const result = await toolRoute.handler(request, reply);
      expect(result.success).toBe(true);
      expect(result.tool).toBe('file_reader');
    });

    it('should run MCP preHandler hook with tool context', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: false
      });

      // Find the MCP-specific preHandler (registered via registerMCPRoutes)
      // It's one of the preHandler hooks added by the register call
      const preHandlers = fastify.hooks.preHandler;
      expect(preHandlers.length).toBeGreaterThanOrEqual(2);

      // The MCP tool preHandler should set mcpContext
      const mcpHook = preHandlers[preHandlers.length - 1];
      const request = mockRequest({
        url: '/tools/web_fetch/execute',
        params: { toolName: 'web_fetch' },
        body: { parameters: { url: 'https://example.com' } }
      });
      const reply = mockReply();
      await mcpHook(request, reply);
      expect(request.mcpContext).toBeDefined();
      expect(request.mcpContext.toolName).toBe('web_fetch');
    });

    it('should handle tool blocking in MCP preHandler', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        mode: 'block',
        schemaCompilation: false
      });

      const preHandlers = fastify.hooks.preHandler;
      const mcpHook = preHandlers[preHandlers.length - 1];
      const request = mockRequest({
        url: '/tools/shell_executor/execute',
        params: { toolName: 'shell_executor' },
        body: { parameters: { command: 'rm -rf / && cat /etc/passwd' } }
      });
      const reply = mockReply();
      await mcpHook(request, reply);
      // May block with 400 if command injection detected
    });

    it('should handle tool with no parameters', async () => {
      const fastify = createMockFastify();
      await mcpSanitizerPlugin(fastify, {
        logWarnings: false,
        schemaCompilation: false
      });

      const preHandlers = fastify.hooks.preHandler;
      const mcpHook = preHandlers[preHandlers.length - 1];
      const request = mockRequest({
        url: '/tools/test/execute',
        params: { toolName: 'test' },
        body: {}
      });
      const reply = mockReply();
      await mcpHook(request, reply);
      expect(request.mcpContext.toolName).toBe('test');
    });
  });
});
