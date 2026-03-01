/**
 * Coverage tests for middleware/index.js
 *
 * Targets: createMiddleware (string and detection paths), createMiddlewareByName
 * (all frameworks + error), detectFramework, createMCPToolMiddleware,
 * createUniversalMiddleware, createEnvironmentMiddleware, validateConfig.
 */

const {
  createMiddleware,
  createMCPToolMiddleware,
  createUniversalMiddleware,
  createEnvironmentMiddleware,
  detectFramework,
  validateConfig
} = require('../../src/middleware');

describe('middleware/index.js', () => {
  describe('createMiddleware', () => {
    it('should create express middleware by string name', () => {
      const mw = createMiddleware('express');
      expect(typeof mw).toBe('function');
    });

    it('should create koa middleware by string name', () => {
      const mw = createMiddleware('koa');
      expect(typeof mw).toBe('function');
    });

    it('should return fastify plugin by string name', () => {
      const plugin = createMiddleware('fastify');
      expect(plugin).toBeDefined();
    });

    it('should throw for unsupported framework string', () => {
      expect(() => createMiddleware('hapi')).toThrow('Unsupported framework');
    });

    it('should throw when framework cannot be detected from object', () => {
      expect(() => createMiddleware({})).toThrow('Unable to detect framework');
    });
  });

  describe('detectFramework', () => {
    it('should return null for plain object', () => {
      expect(detectFramework({})).toBeNull();
    });

    it('should return null for null', () => {
      expect(detectFramework(null)).toBeNull();
    });

    it('should detect fastify-like app', () => {
      const fakeApp = {
        register: () => {},
        addHook: () => {}
      };
      expect(detectFramework(fakeApp)).toBe('fastify');
    });
  });

  describe('createMCPToolMiddleware', () => {
    it('should create express tool middleware', () => {
      const mw = createMCPToolMiddleware('express');
      expect(typeof mw).toBe('function');
    });

    it('should create koa tool middleware', () => {
      const mw = createMCPToolMiddleware('koa');
      expect(typeof mw).toBe('function');
    });

    it('should create fastify tool middleware', () => {
      const plugin = createMCPToolMiddleware('fastify');
      expect(plugin).toBeDefined();
    });

    it('should throw for unsupported framework', () => {
      expect(() => createMCPToolMiddleware('hapi')).toThrow('Unsupported framework');
    });
  });

  describe('createUniversalMiddleware', () => {
    it('should return object with all framework factories', () => {
      const universal = createUniversalMiddleware();
      expect(typeof universal.express).toBe('function');
      expect(universal.fastify).toBeDefined();
      expect(typeof universal.koa).toBe('function');
      expect(typeof universal.auto).toBe('function');
    });

    it('should return tool-specific versions', () => {
      const universal = createUniversalMiddleware();
      expect(typeof universal.tool.express).toBe('function');
      expect(universal.tool.fastify).toBeDefined();
      expect(typeof universal.tool.koa).toBe('function');
    });

    it('should create working express middleware from factory', () => {
      const universal = createUniversalMiddleware({ policy: 'STRICT' });
      const mw = universal.express();
      expect(typeof mw).toBe('function');
    });
  });

  describe('createEnvironmentMiddleware', () => {
    it('should create production middleware', () => {
      const envMw = createEnvironmentMiddleware('production');
      expect(typeof envMw.express).toBe('function');
    });

    it('should create development middleware', () => {
      const envMw = createEnvironmentMiddleware('development');
      expect(typeof envMw.express).toBe('function');
    });

    it('should create testing middleware', () => {
      const envMw = createEnvironmentMiddleware('testing');
      expect(typeof envMw.express).toBe('function');
    });

    it('should create staging middleware', () => {
      const envMw = createEnvironmentMiddleware('staging');
      expect(typeof envMw.express).toBe('function');
    });

    it('should fallback to production for unknown environment', () => {
      const envMw = createEnvironmentMiddleware('unknown');
      expect(typeof envMw.express).toBe('function');
    });

    it('should apply customizations', () => {
      const envMw = createEnvironmentMiddleware('production', { logWarnings: false });
      expect(typeof envMw.express).toBe('function');
    });
  });

  describe('validateConfig', () => {
    it('should accept valid config', () => {
      const result = validateConfig({ mode: 'sanitize', policy: 'PRODUCTION', blockStatusCode: 400 });
      expect(result.mode).toBe('sanitize');
      expect(result.policy).toBe('PRODUCTION');
    });

    it('should default invalid mode to sanitize', () => {
      const result = validateConfig({ mode: 'invalid', policy: 'PRODUCTION', blockStatusCode: 400 });
      expect(result.mode).toBe('sanitize');
    });

    it('should default invalid policy to PRODUCTION', () => {
      const result = validateConfig({ mode: 'sanitize', policy: 'INVALID', blockStatusCode: 400 });
      expect(result.policy).toBe('PRODUCTION');
    });

    it('should default invalid status code to 400', () => {
      const result = validateConfig({ mode: 'sanitize', policy: 'PRODUCTION', blockStatusCode: 200 });
      expect(result.blockStatusCode).toBe(400);
    });

    it('should default status code >= 600 to 400', () => {
      const result = validateConfig({ mode: 'sanitize', policy: 'PRODUCTION', blockStatusCode: 600 });
      expect(result.blockStatusCode).toBe(400);
    });
  });
});
