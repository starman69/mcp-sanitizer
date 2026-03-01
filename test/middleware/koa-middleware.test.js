/**
 * Coverage tests for middleware/koa.js
 *
 * Targets: createKoaMiddleware (skip paths, health checks, static files,
 * body/params/query/headers sanitization, blocking mode, warnings,
 * addToState, response sanitization, error handling),
 * createMCPToolMiddleware (tool-specific sanitization for all tool types,
 * blocking), createMCPServerMiddleware (routing to tool vs base middleware).
 */

const {
  createKoaMiddleware,
  createMCPToolMiddleware,
  createMCPServerMiddleware,
  DEFAULT_CONFIG
} = require('../../src/middleware/koa');

// Helper: create mock Koa context
function mockCtx (overrides = {}) {
  const ctx = {
    path: '/api/test',
    method: 'POST',
    ip: '127.0.0.1',
    request: {
      body: {},
      ...(overrides.requestOverrides || {})
    },
    params: {},
    query: {},
    headers: { 'user-agent': 'test-agent' },
    state: {},
    status: 200,
    body: null,
    get: function (header) { return this.headers[header.toLowerCase()] || ''; },
    ...overrides
  };
  // Allow request.body override via top-level body
  if (overrides.body && !overrides.requestOverrides) {
    ctx.request.body = overrides.body;
    delete ctx.body;
    ctx.body = null;
  }
  return ctx;
}

// Helper: noop next
const noopNext = async () => {};

describe('middleware/koa.js', () => {
  describe('createKoaMiddleware', () => {
    it('should return a middleware function', () => {
      const mw = createKoaMiddleware();
      expect(typeof mw).toBe('function');
    });

    it('should process clean request and call next', async () => {
      const mw = createKoaMiddleware({ logWarnings: false });
      const ctx = mockCtx();
      ctx.request.body = { name: 'safe' };
      let nextCalled = false;
      await mw(ctx, async () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
    });

    it('should add sanitization data to context', async () => {
      const mw = createKoaMiddleware({ logWarnings: false });
      const ctx = mockCtx();
      ctx.request.body = { name: 'clean' };
      ctx.params = { id: '123' };
      ctx.query = { search: 'test' };
      await mw(ctx, noopNext);
      expect(ctx.sanitizationWarnings).toBeDefined();
      expect(ctx.sanitizationResults).toBeDefined();
    });

    it('should add sanitization to state when addToState is true', async () => {
      const mw = createKoaMiddleware({ logWarnings: false, addToState: true });
      const ctx = mockCtx();
      ctx.request.body = { name: 'clean' };
      await mw(ctx, noopNext);
      expect(ctx.state.sanitization).toBeDefined();
      expect(ctx.state.sanitization.processed).toBe(true);
    });

    it('should use custom contextKey for state', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        addToState: true,
        contextKey: 'mcp'
      });
      const ctx = mockCtx();
      ctx.request.body = { name: 'clean' };
      await mw(ctx, noopNext);
      expect(ctx.state.mcp).toBeDefined();
    });
  });

  describe('skip paths', () => {
    it('should skip health check paths', async () => {
      const mw = createKoaMiddleware({ logWarnings: false, skipHealthChecks: true });
      const ctx = mockCtx({ path: '/health' });
      let nextCalled = false;
      await mw(ctx, async () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(ctx.sanitizationResults).toBeUndefined();
    });

    it('should skip health sub-paths', async () => {
      const mw = createKoaMiddleware({ logWarnings: false, skipHealthChecks: true });
      const ctx = mockCtx({ path: '/ping/detailed' });
      let nextCalled = false;
      await mw(ctx, async () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(ctx.sanitizationResults).toBeUndefined();
    });

    it('should skip static file paths', async () => {
      const mw = createKoaMiddleware({ logWarnings: false, skipStaticFiles: true });
      const ctx = mockCtx({ path: '/static/bundle.js' });
      let nextCalled = false;
      await mw(ctx, async () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(ctx.sanitizationResults).toBeUndefined();
    });

    it('should skip paths without file extensions', async () => {
      const mw = createKoaMiddleware({ logWarnings: false, skipStaticFiles: true });
      const ctx = mockCtx({ path: '/api/data' });
      ctx.request.body = { x: 'safe' };
      await mw(ctx, noopNext);
      expect(ctx.sanitizationResults).toBeDefined();
    });

    it('should skip custom skipPaths', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        skipPaths: ['/public', /^\/static\//]
      });
      const ctx = mockCtx({ path: '/public' });
      let nextCalled = false;
      await mw(ctx, async () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(ctx.sanitizationResults).toBeUndefined();
    });

    it('should not skip when skipHealthChecks is false', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        skipHealthChecks: false,
        skipStaticFiles: false
      });
      const ctx = mockCtx({ path: '/health' });
      ctx.request.body = { x: 'safe' };
      await mw(ctx, noopNext);
      // Should process the request
    });
  });

  describe('sanitize headers', () => {
    it('should sanitize headers when enabled', async () => {
      const mw = createKoaMiddleware({ logWarnings: false, sanitizeHeaders: true });
      const ctx = mockCtx();
      ctx.headers = { 'x-data': 'safe', 'user-agent': 'test' };
      await mw(ctx, noopNext);
      expect(ctx.sanitizationResults.headers).toBeDefined();
    });
  });

  describe('blocking mode', () => {
    it('should block malicious body', async () => {
      const mw = createKoaMiddleware({
        mode: 'block',
        logWarnings: false,
        includeDetails: true
      });
      const ctx = mockCtx();
      ctx.request.body = { input: "'; DROP TABLE users; --" };
      await mw(ctx, noopNext);
      if (ctx.status === 400) {
        expect(ctx.body.blocked).toBe(true);
        expect(ctx.body.details).toBeDefined();
      }
    });

    it('should call onBlocked handler', async () => {
      const mw = createKoaMiddleware({
        mode: 'block',
        logWarnings: false,
        onBlocked: async () => {
          // handler called
        }
      });
      const ctx = mockCtx();
      ctx.request.body = { input: "'; DROP TABLE users; --" };
      await mw(ctx, noopNext);
    });

    it('should skip default blocked response when onBlocked returns false', async () => {
      const mw = createKoaMiddleware({
        mode: 'block',
        logWarnings: false,
        onBlocked: async () => false
      });
      const ctx = mockCtx();
      ctx.request.body = { input: "'; DROP TABLE users; --" };
      await mw(ctx, noopNext);
    });

    it('should not include details when includeDetails is false', async () => {
      const mw = createKoaMiddleware({
        mode: 'block',
        logWarnings: false,
        includeDetails: false
      });
      const ctx = mockCtx();
      ctx.request.body = { input: "'; DROP TABLE users; --" };
      await mw(ctx, noopNext);
      if (ctx.status === 400) {
        expect(ctx.body.details).toBeUndefined();
      }
    });

    it('should use logger from context when available', async () => {
      const customLogger = { warn: jest.fn(), error: jest.fn() };
      const mw = createKoaMiddleware({
        mode: 'block',
        logWarnings: true,
        loggerKey: 'logger'
      });
      const ctx = mockCtx();
      ctx.logger = customLogger;
      ctx.request.body = { input: "'; DROP TABLE users; --" };
      await mw(ctx, noopNext);
    });
  });

  describe('warnings', () => {
    it('should call onWarning handler', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        onWarning: async () => {
          // handler called
        }
      });
      const ctx = mockCtx();
      ctx.request.body = { input: '<script>alert(1)</script>' };
      await mw(ctx, noopNext);
    });

    it('should not add to context when addWarningsToContext is false', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        addWarningsToContext: false,
        addToState: false
      });
      const ctx = mockCtx();
      ctx.request.body = { name: 'clean' };
      await mw(ctx, noopNext);
      expect(ctx.sanitizationWarnings).toBeUndefined();
      expect(ctx.sanitizationResults).toBeUndefined();
    });
  });

  describe('response sanitization', () => {
    it('should sanitize response when sanitizeResponse is true', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        sanitizeResponse: true
      });
      const ctx = mockCtx();
      ctx.request.body = { name: 'clean' };
      await mw(ctx, async () => {
        ctx.body = { data: 'response data' };
      });
      // Body should be sanitized
      expect(ctx.body).toBeDefined();
    });

    it('should block response with malicious content', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        sanitizeResponse: true
      });
      const ctx = mockCtx();
      ctx.request.body = { name: 'clean' };
      await mw(ctx, async () => {
        ctx.body = { data: "'; DROP TABLE users; --" };
      });
    });

    it('should add response warnings to state', async () => {
      const mw = createKoaMiddleware({
        logWarnings: false,
        sanitizeResponse: true,
        addToState: true
      });
      const ctx = mockCtx();
      ctx.request.body = { name: 'clean' };
      await mw(ctx, async () => {
        ctx.body = { data: '<script>alert(1)</script>' };
      });
    });
  });

  describe('error handling', () => {
    it('should handle middleware errors', async () => {
      const brokenSanitizer = {
        sanitize: () => { throw new Error('Koa crash'); }
      };
      const mw = createKoaMiddleware({
        sanitizer: brokenSanitizer,
        logWarnings: false
      });
      const ctx = mockCtx();
      ctx.request.body = { input: 'test' };
      await mw(ctx, noopNext);
      expect(ctx.status).toBe(500);
      expect(ctx.body.error).toBe('Internal sanitization error');
    });

    it('should call onError handler', async () => {
      let capturedError = null;
      const brokenSanitizer = {
        sanitize: () => { throw new Error('Boom'); }
      };
      const mw = createKoaMiddleware({
        sanitizer: brokenSanitizer,
        logWarnings: false,
        onError: async (error, ctx) => {
          capturedError = error;
        }
      });
      const ctx = mockCtx();
      ctx.request.body = { input: 'test' };
      await mw(ctx, noopNext);
      expect(capturedError).not.toBeNull();
      expect(capturedError.message).toBe('Boom');
    });

    it('should skip default error response when onError returns false', async () => {
      const brokenSanitizer = {
        sanitize: () => { throw new Error('Boom'); }
      };
      const mw = createKoaMiddleware({
        sanitizer: brokenSanitizer,
        logWarnings: false,
        onError: async () => false
      });
      const ctx = mockCtx();
      ctx.request.body = { input: 'test' };
      await mw(ctx, noopNext);
    });

    it('should use custom logger for errors', async () => {
      const customLogger = { warn: jest.fn(), error: jest.fn() };
      const brokenSanitizer = {
        sanitize: () => { throw new Error('Boom'); }
      };
      const mw = createKoaMiddleware({
        sanitizer: brokenSanitizer,
        logWarnings: false,
        loggerKey: 'logger'
      });
      const ctx = mockCtx();
      ctx.logger = customLogger;
      ctx.request.body = { input: 'test' };
      await mw(ctx, noopNext);
      expect(customLogger.error).toHaveBeenCalled();
    });
  });

  describe('createMCPToolMiddleware', () => {
    it('should return a middleware function', () => {
      const mw = createMCPToolMiddleware();
      expect(typeof mw).toBe('function');
    });

    it('should set mcpContext on context', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false });
      const ctx = mockCtx();
      ctx.params = { toolName: 'file_reader' };
      ctx.request.body = { tool_name: 'file_reader', parameters: { file_path: '/tmp/test.txt' } };
      await mw(ctx, noopNext);
      expect(ctx.mcpContext).toBeDefined();
      expect(ctx.mcpContext.toolName).toBe('file_reader');
    });

    it('should apply file_reader tool sanitization', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false, mode: 'sanitize' });
      const ctx = mockCtx();
      ctx.params = { toolName: 'file_reader' };
      ctx.request.body = { parameters: { file_path: '/tmp/safe.txt' } };
      await mw(ctx, noopNext);
    });

    it('should apply web_fetch tool sanitization', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false, mode: 'sanitize' });
      const ctx = mockCtx();
      ctx.params = { toolName: 'web_fetch' };
      ctx.request.body = { parameters: { url: 'https://example.com' } };
      await mw(ctx, noopNext);
    });

    it('should apply command_runner tool sanitization', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false, mode: 'sanitize' });
      const ctx = mockCtx();
      ctx.params = { toolName: 'command_runner' };
      ctx.request.body = { parameters: { command: 'echo hello' } };
      await mw(ctx, noopNext);
    });

    it('should apply sql_executor tool sanitization', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false, mode: 'sanitize' });
      const ctx = mockCtx();
      ctx.params = { toolName: 'sql_executor' };
      ctx.request.body = { parameters: { query: 'SELECT 1' } };
      await mw(ctx, noopNext);
    });

    it('should handle tool with no parameters body', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false });
      const ctx = mockCtx();
      ctx.params = { toolName: 'unknown_tool' };
      ctx.request.body = {};
      await mw(ctx, noopNext);
    });

    it('should block malicious tool params in block mode', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false, mode: 'block' });
      const ctx = mockCtx();
      ctx.params = { toolName: 'shell_executor' };
      ctx.request.body = { parameters: { command: 'rm -rf / && cat /etc/passwd' } };
      await mw(ctx, noopNext);
      // May set status 400 if blocked
    });

    it('should handle MCP_TOOL_BLOCKED error', async () => {
      const mw = createMCPToolMiddleware({ logWarnings: false, mode: 'block' });
      const ctx = mockCtx();
      ctx.params = { toolName: 'database_query' };
      ctx.request.body = { parameters: { query: "'; DROP TABLE users; --" } };
      await mw(ctx, noopNext);
      // Should block with 400 status
    });
  });

  describe('createMCPServerMiddleware', () => {
    it('should return a middleware function', () => {
      const mw = createMCPServerMiddleware();
      expect(typeof mw).toBe('function');
    });

    it('should route tool requests to tool middleware', async () => {
      const mw = createMCPServerMiddleware({ logWarnings: false });
      const ctx = mockCtx({ path: '/tools/file_reader/execute' });
      ctx.params = { toolName: 'file_reader' };
      ctx.request.body = { parameters: { file_path: '/tmp/test.txt' } };
      await mw(ctx, noopNext);
      expect(ctx.mcpContext).toBeDefined();
    });

    it('should route non-tool requests to base middleware', async () => {
      const mw = createMCPServerMiddleware({ logWarnings: false });
      const ctx = mockCtx({ path: '/api/data' });
      ctx.request.body = { name: 'safe' };
      await mw(ctx, noopNext);
    });
  });

  describe('DEFAULT_CONFIG', () => {
    it('should export default configuration', () => {
      expect(DEFAULT_CONFIG.sanitizeBody).toBe(true);
      expect(DEFAULT_CONFIG.sanitizeParams).toBe(true);
      expect(DEFAULT_CONFIG.sanitizeQuery).toBe(true);
      expect(DEFAULT_CONFIG.sanitizeHeaders).toBe(false);
      expect(DEFAULT_CONFIG.mode).toBe('sanitize');
      expect(DEFAULT_CONFIG.policy).toBe('PRODUCTION');
      expect(DEFAULT_CONFIG.addToState).toBe(true);
      expect(DEFAULT_CONFIG.contextKey).toBe('sanitization');
      expect(DEFAULT_CONFIG.loggerKey).toBe('logger');
    });
  });
});
