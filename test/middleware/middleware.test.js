/**
 * Test file for MCP Sanitizer Middleware
 *
 * This test file demonstrates and validates the middleware functionality
 * across different Node.js frameworks (Express, Fastify, Koa).
 */

const { describe, it, expect, beforeEach } = require('@jest/globals'); // afterEach unused
// const request = require('supertest') // Unused - commented to fix ESLint
const MCPSanitizer = require('../../src/index');

// Mock framework apps for testing
let mockExpress, mockFastify, mockKoa;

// Import middleware modules
const middlewareModule = require('../../src/middleware');
const { express, fastify, koa } = middlewareModule;

describe('MCP Sanitizer Middleware', () => {
  beforeEach(() => {
    // Reset mocks before each test
    mockExpress = createMockExpressApp();
    mockFastify = createMockFastifyApp();
    mockKoa = createMockKoaApp();
  });

  describe('Framework Detection', () => {
    it('should detect Express app correctly', () => {
      const framework = middlewareModule.detectFramework(mockExpress);
      expect(framework).toBe('express');
    });

    it('should detect Fastify app correctly', () => {
      const framework = middlewareModule.detectFramework(mockFastify);
      expect(framework).toBe('fastify');
    });

    it('should detect Koa app correctly', () => {
      const framework = middlewareModule.detectFramework(mockKoa);
      expect(framework).toBe('koa');
    });

    it('should return null for unknown framework', () => {
      const framework = middlewareModule.detectFramework({ unknown: true });
      expect(framework).toBe(null);
    });
  });

  describe('Configuration Validation', () => {
    it('should validate and normalize configuration', () => {
      const config = {
        mode: 'invalid',
        policy: 'INVALID',
        blockStatusCode: 999
      };

      const validated = middlewareModule.validateConfig(config);
      expect(validated.mode).toBe('sanitize');
      expect(validated.policy).toBe('PRODUCTION');
      expect(validated.blockStatusCode).toBe(400);
    });

    it('should preserve valid configuration', () => {
      const config = {
        mode: 'block',
        policy: 'STRICT',
        blockStatusCode: 403
      };

      const validated = middlewareModule.validateConfig(config);
      expect(validated.mode).toBe('block');
      expect(validated.policy).toBe('STRICT');
      expect(validated.blockStatusCode).toBe(403);
    });
  });

  describe('Express Middleware', () => {
    it('should create Express middleware with default configuration', () => {
      const middleware = express.createExpressMiddleware();
      expect(typeof middleware).toBe('function');
      expect(middleware.length).toBe(3); // req, res, next
    });

    it('should sanitize request body in sanitize mode', () => {
      const onWarning = jest.fn();
      const middleware = express.createExpressMiddleware({
        mode: 'sanitize',
        onWarning
      });

      const mockReq = createMockExpressRequest({
        body: {
          command: 'ls; rm -rf /', // Malicious command
          file_path: 'normal.txt'
        }
      });
      const mockRes = createMockExpressResponse();
      const mockNext = jest.fn();

      middleware(mockReq, mockRes, mockNext);

      // Should proceed to next middleware
      expect(mockNext).toHaveBeenCalled();
      // Should have sanitization warnings added to request
      expect(mockReq.sanitizationWarnings).toBeDefined();
    });

    it('should block request in block mode with malicious content', () => {
      const onBlocked = jest.fn(() => false); // Return false to prevent default response
      const middleware = express.createExpressMiddleware({
        mode: 'block',
        onBlocked
      });

      const mockReq = createMockExpressRequest({
        body: {
          command: 'ls; rm -rf /' // Malicious command
        }
      });
      const mockRes = createMockExpressResponse();
      const mockNext = jest.fn();

      middleware(mockReq, mockRes, mockNext);

      // Should not proceed to next middleware
      expect(mockNext).not.toHaveBeenCalled();
      // Should call onBlocked callback
      expect(onBlocked).toHaveBeenCalled();
    });

    it('should skip health check requests', () => {
      const middleware = express.createExpressMiddleware({
        skipHealthChecks: true
      });

      const mockReq = createMockExpressRequest({ path: '/health' });
      const mockRes = createMockExpressResponse();
      const mockNext = jest.fn();

      middleware(mockReq, mockRes, mockNext);

      // Should skip processing and go to next
      expect(mockNext).toHaveBeenCalled();
    });

    it('should create MCP tool-specific middleware', () => {
      const toolMiddleware = express.createMCPToolMiddleware({
        toolSpecificSanitization: true
      });

      expect(typeof toolMiddleware).toBe('function');

      const mockReq = createMockExpressRequest({
        params: { toolName: 'file_reader' },
        body: {
          parameters: {
            file_path: '../../../etc/passwd' // Path traversal attempt
          }
        }
      });
      const mockRes = createMockExpressResponse();
      const mockNext = jest.fn();

      toolMiddleware(mockReq, mockRes, mockNext);

      expect(mockReq.mcpContext).toBeDefined();
      expect(mockReq.mcpContext.toolName).toBe('file_reader');
    });
  });

  describe('Fastify Plugin', () => {
    it('should be a valid Fastify plugin function', () => {
      expect(typeof fastify).toBe('function');
      // Fastify plugins should be async functions
      expect(fastify.constructor.name).toBe('AsyncFunction');
    });

    it('should have plugin metadata', () => {
      // Check for fastify-plugin metadata
      expect(fastify[Symbol.for('skip-override')]).toBe(true);
      expect(fastify[Symbol.for('plugin-meta')]).toBeDefined();
    });

    it('should register hooks on Fastify instance', async () => {
      const mockFastifyInstance = createMockFastifyApp();
      const options = { policy: 'PRODUCTION' };

      await fastify(mockFastifyInstance, options);

      // Verify hooks were added
      expect(mockFastifyInstance.addHook).toHaveBeenCalled();
      expect(mockFastifyInstance.decorateRequest).toHaveBeenCalled();
    });
  });

  describe('Koa Middleware', () => {
    it('should create Koa middleware with default configuration', () => {
      const middleware = koa.createKoaMiddleware();
      expect(typeof middleware).toBe('function');
      expect(middleware.constructor.name).toBe('AsyncFunction');
    });

    it('should sanitize request context in sanitize mode', async () => {
      const onWarning = jest.fn();
      const middleware = koa.createKoaMiddleware({
        mode: 'sanitize',
        onWarning
      });

      const mockCtx = createMockKoaContext({
        request: {
          body: {
            query: 'SELECT * FROM users; DROP TABLE users;' // SQL injection
          }
        }
      });
      const mockNext = jest.fn().mockResolvedValue();

      await middleware(mockCtx, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockCtx.sanitizationWarnings).toBeDefined();
    });

    it('should add sanitization data to state', async () => {
      const middleware = koa.createKoaMiddleware({
        addToState: true,
        contextKey: 'mcp'
      });

      const mockCtx = createMockKoaContext({
        request: { body: { test: 'safe content' } },
        state: {}
      });
      const mockNext = jest.fn().mockResolvedValue();

      await middleware(mockCtx, mockNext);

      expect(mockCtx.state.mcp).toBeDefined();
      expect(mockCtx.state.mcp.processed).toBe(true);
    });

    it('should create MCP server middleware', () => {
      const serverMiddleware = koa.createMCPServerMiddleware({
        toolSpecificSanitization: true
      });

      expect(typeof serverMiddleware).toBe('function');
      expect(serverMiddleware.constructor.name).toBe('AsyncFunction');
    });
  });

  describe('Universal Middleware Factory', () => {
    it('should create universal middleware with all frameworks', () => {
      const universal = middlewareModule.createUniversalMiddleware({
        policy: 'PRODUCTION',
        mode: 'block'
      });

      expect(universal.express).toBeDefined();
      expect(universal.fastify).toBeDefined();
      expect(universal.koa).toBeDefined();
      expect(universal.auto).toBeDefined();
      expect(universal.tool).toBeDefined();
    });

    it('should auto-detect framework and return appropriate middleware', () => {
      const universal = middlewareModule.createUniversalMiddleware();

      const expressMiddleware = universal.auto(mockExpress);
      const koaMiddleware = universal.auto(mockKoa);

      expect(typeof expressMiddleware).toBe('function');
      expect(typeof koaMiddleware).toBe('function');
      expect(expressMiddleware.length).toBe(3); // Express: req, res, next
      expect(koaMiddleware.constructor.name).toBe('AsyncFunction'); // Koa: async
    });
  });

  describe('Environment-specific Configuration', () => {
    it('should create development environment middleware', () => {
      const devMiddleware = middlewareModule.createEnvironmentMiddleware('development');

      expect(devMiddleware.express).toBeDefined();
      expect(devMiddleware.fastify).toBeDefined();
      expect(devMiddleware.koa).toBeDefined();
    });

    it('should create production environment middleware', () => {
      const prodMiddleware = middlewareModule.createEnvironmentMiddleware('production');

      expect(prodMiddleware.express).toBeDefined();
      expect(prodMiddleware.fastify).toBeDefined();
      expect(prodMiddleware.koa).toBeDefined();
    });

    it('should apply environment-specific defaults', () => {
      const testMiddleware = middlewareModule.createEnvironmentMiddleware('testing', {
        customOption: true
      });

      expect(testMiddleware).toBeDefined();
    });
  });

  describe('Tool-specific Sanitization', () => {
    it('should handle file_reader tool parameters', () => {
      const mockReq = createMockExpressRequest({
        params: { toolName: 'file_reader' },
        body: {
          parameters: {
            file_path: '../../../etc/passwd'
          }
        }
      });

      // This would normally be called internally by the middleware
      const sanitizer = new MCPSanitizer({ policy: 'PRODUCTION' });
      const result = sanitizer.sanitize(mockReq.body.parameters.file_path, { type: 'file_path' });

      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings.some(w => typeof w === 'string' && w.includes('blocked pattern'))).toBe(true);
    });

    it('should handle command execution tool parameters', () => {
      const mockReq = createMockExpressRequest({
        params: { toolName: 'shell_executor' },
        body: {
          parameters: {
            command: 'ls; rm -rf /'
          }
        }
      });

      const sanitizer = new MCPSanitizer({ policy: 'PRODUCTION' });
      const result = sanitizer.sanitize(mockReq.body.parameters.command, { type: 'command' });

      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings.some(w => typeof w === 'string' && w.includes('blocked pattern'))).toBe(true);
    });
  });
});

// Mock helper functions
function createMockExpressApp () {
  return {
    use: jest.fn(),
    get: jest.fn(),
    post: jest.fn(),
    constructor: { name: 'Function' }
  };
}

function createMockFastifyApp () {
  return {
    register: jest.fn(),
    addHook: jest.fn(),
    decorateRequest: jest.fn(),
    decorate: jest.fn(),
    setSchemaCompiler: jest.fn()
  };
}

function createMockKoaApp () {
  return {
    use: jest.fn(),
    constructor: { name: 'Application' }
  };
}

function createMockExpressRequest (overrides = {}) {
  return {
    ip: '127.0.0.1',
    path: '/api/test',
    method: 'POST',
    body: {},
    params: {},
    query: {},
    headers: { 'user-agent': 'test-agent' },
    get: jest.fn((header) => 'test-value'),
    ...overrides
  };
}

function createMockExpressResponse () {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis()
  };
  return res;
}

function createMockKoaContext (overrides = {}) {
  return {
    ip: '127.0.0.1',
    path: '/api/test',
    method: 'POST',
    request: { body: {} },
    params: {},
    query: {},
    headers: { 'user-agent': 'test-agent' },
    get: jest.fn((header) => 'test-value'),
    state: {},
    ...overrides
  };
}
